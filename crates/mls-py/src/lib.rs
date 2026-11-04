//! PyO3 layer: argument extraction, object creation, runtime detachment and
//! exception conversion only. All protocol decisions live in `mls-facade`.
//!
//! Every method copies/pins its inputs, detaches from the Python runtime for
//! the whole MLS operation (the facade serializes on its own locks), then
//! reattaches to build Python objects. No Python object is touched while a
//! facade lock is held.

use mls_facade as facade;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyBool, PyBytes, PyInt, PyTuple};

create_exception!(
    mls_py,
    MlsError,
    PyException,
    "MLS operation failed. `.code` is a stable string; `.message` is human-readable."
);

fn to_py_err(py: Python<'_>, e: facade::Error) -> PyErr {
    let err = MlsError::new_err(format!("{}: {}", e.code.as_str(), e.message));
    let value = err.value(py);
    // Attribute setting on a fresh exception instance cannot meaningfully fail.
    let _ = value.setattr("code", e.code.as_str());
    let _ = value.setattr("message", e.message);
    err
}

fn invalid_arg(py: Python<'_>, message: &'static str) -> PyErr {
    to_py_err(
        py,
        facade::Error {
            code: facade::ErrorCode::InvalidArgument,
            message,
        },
    )
}

/// Strict integer extraction: rejects bool and non-int types with TypeError,
/// and out-of-range values (negative, too large) with MlsError(invalid_argument).
fn int_arg<T>(obj: &Bound<'_, PyAny>, out_of_range: &'static str) -> PyResult<T>
where
    T: for<'a, 'py> FromPyObject<'a, 'py>,
{
    if obj.is_instance_of::<PyBool>() || !obj.is_instance_of::<PyInt>() {
        return Err(PyTypeError::new_err("expected an int"));
    }
    obj.extract::<T>()
        .map_err(|_| invalid_arg(obj.py(), out_of_range))
}

fn bytes<'py>(py: Python<'py>, v: Vec<u8>) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &v)
}

/// An MLS client: one identity, one signing key and one cipher suite, with a
/// process-local in-memory store. Signing keys never leave Rust.
#[pyclass(frozen, module = "mls_py")]
struct Client {
    inner: facade::Client,
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (identity, *, cipher_suite = None, max_message_size = None))]
    fn new(
        py: Python<'_>,
        identity: PyBackedBytes,
        cipher_suite: Option<&Bound<'_, PyAny>>,
        max_message_size: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let cs: u16 = match cipher_suite {
            Some(o) => int_arg(o, "cipher_suite out of range").map_err(|e| {
                if e.is_instance_of::<MlsError>(py) {
                    to_py_err(
                        py,
                        facade::Error {
                            code: facade::ErrorCode::UnsupportedCipherSuite,
                            message: "cipher suite not in SUPPORTED_CIPHER_SUITES",
                        },
                    )
                } else {
                    e
                }
            })?,
            None => facade::DEFAULT_CIPHER_SUITE,
        };
        let max: usize = match max_message_size {
            Some(o) => int_arg(o, "max_message_size out of range")?,
            None => facade::DEFAULT_MAX_MESSAGE_SIZE,
        };
        let inner = py
            .detach(|| facade::Client::new(&identity, cs, max))
            .map_err(|e| to_py_err(py, e))?;
        Ok(Self { inner })
    }

    #[getter]
    fn cipher_suite(&self) -> u16 {
        self.inner.cipher_suite()
    }

    #[getter]
    fn max_message_size(&self) -> usize {
        self.inner.max_message_size()
    }

    /// A fresh, single-use key package (serialized MLSMessage).
    fn key_package<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let out = py
            .detach(|| self.inner.key_package())
            .map_err(|e| to_py_err(py, e))?;
        Ok(bytes(py, out))
    }

    fn create_group(&self, py: Python<'_>) -> PyResult<Group> {
        let g = py
            .detach(|| self.inner.create_group())
            .map_err(|e| to_py_err(py, e))?;
        Ok(Group { inner: g })
    }

    fn join(&self, py: Python<'_>, welcome: PyBackedBytes) -> PyResult<Group> {
        let g = py
            .detach(|| self.inner.join(&welcome))
            .map_err(|e| to_py_err(py, e))?;
        Ok(Group { inner: g })
    }

    fn load_group(&self, py: Python<'_>, group_id: PyBackedBytes) -> PyResult<Group> {
        let g = py
            .detach(|| self.inner.load_group(&group_id))
            .map_err(|e| to_py_err(py, e))?;
        Ok(Group { inner: g })
    }

    fn __repr__(&self) -> String {
        format!("<mls_py.Client cipher_suite={}>", self.inner.cipher_suite())
    }
}

/// Handle to one MLS group (at most one live handle per group per client).
#[pyclass(frozen, module = "mls_py")]
struct Group {
    inner: facade::Group,
}

#[pymethods]
impl Group {
    #[getter]
    fn group_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.group_id())
    }

    #[getter]
    fn is_active(&self, py: Python<'_>) -> PyResult<bool> {
        py.detach(|| self.inner.is_active())
            .map_err(|e| to_py_err(py, e))
    }

    #[getter]
    fn epoch(&self, py: Python<'_>) -> PyResult<u64> {
        py.detach(|| self.inner.epoch())
            .map_err(|e| to_py_err(py, e))
    }

    #[getter]
    fn leaf_index(&self, py: Python<'_>) -> PyResult<u32> {
        py.detach(|| self.inner.leaf_index())
            .map_err(|e| to_py_err(py, e))
    }

    #[getter]
    fn cipher_suite(&self, py: Python<'_>) -> PyResult<u16> {
        py.detach(|| self.inner.cipher_suite())
            .map_err(|e| to_py_err(py, e))
    }

    #[getter]
    fn has_pending_commit(&self, py: Python<'_>) -> PyResult<bool> {
        py.detach(|| self.inner.has_pending_commit())
            .map_err(|e| to_py_err(py, e))
    }

    /// `[(leaf_index, identity), ...]` for current members.
    #[getter]
    fn members<'py>(&self, py: Python<'py>) -> PyResult<Vec<(u32, Bound<'py, PyBytes>)>> {
        let m = py
            .detach(|| self.inner.members())
            .map_err(|e| to_py_err(py, e))?;
        Ok(m.into_iter().map(|(i, id)| (i, bytes(py, id))).collect())
    }

    /// Commit adding a member. Returns `(commit, welcome)`; pending until
    /// `apply_pending()`.
    fn add<'py>(
        &self,
        py: Python<'py>,
        key_package: PyBackedBytes,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let (c, w) = py
            .detach(|| self.inner.add(&key_package))
            .map_err(|e| to_py_err(py, e))?;
        PyTuple::new(py, [bytes(py, c), bytes(py, w)])
    }

    /// Commit removing the member at `leaf_index`; pending until applied.
    fn remove<'py>(
        &self,
        py: Python<'py>,
        leaf_index: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let idx: u32 = int_arg(leaf_index, "leaf_index out of range")?;
        let c = py
            .detach(|| self.inner.remove(idx))
            .map_err(|e| to_py_err(py, e))?;
        Ok(bytes(py, c))
    }

    /// Commit refreshing our own leaf key and including received proposals.
    fn commit<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let c = py
            .detach(|| self.inner.commit())
            .map_err(|e| to_py_err(py, e))?;
        Ok(bytes(py, c))
    }

    fn apply_pending(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.inner.apply_pending())
            .map_err(|e| to_py_err(py, e))
    }

    fn discard_pending(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.inner.discard_pending())
            .map_err(|e| to_py_err(py, e))
    }

    fn process(&self, py: Python<'_>, message: PyBackedBytes) -> PyResult<Event> {
        let ev = py
            .detach(|| self.inner.process(&message))
            .map_err(|e| to_py_err(py, e))?;
        Ok(Event::from(ev))
    }

    #[pyo3(signature = (data, aad = None))]
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        data: PyBackedBytes,
        aad: Option<PyBackedBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let out = py
            .detach(|| self.inner.encrypt(&data, aad.as_deref().unwrap_or(&[])))
            .map_err(|e| to_py_err(py, e))?;
        Ok(bytes(py, out))
    }

    fn export_secret<'py>(
        &self,
        py: Python<'py>,
        label: PyBackedBytes,
        context: PyBackedBytes,
        length: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let len: usize = int_arg(length, "length must be in 1..=1024")?;
        let out = py
            .detach(|| self.inner.export_secret(&label, &context, len))
            .map_err(|e| to_py_err(py, e))?;
        Ok(bytes(py, out))
    }

    fn __repr__(&self) -> String {
        "<mls_py.Group>".to_string()
    }
}

/// Immutable result of `Group.process()`.
#[pyclass(frozen, eq, hash, module = "mls_py")]
#[derive(PartialEq, Eq, Hash)]
struct Event {
    kind_: &'static str,
    data_: Option<Vec<u8>>,
    aad_: Vec<u8>,
    sender_index_: Option<u32>,
    epoch_: u64,
    removed_: bool,
}

impl From<facade::Event> for Event {
    fn from(e: facade::Event) -> Self {
        Self {
            kind_: e.kind.as_str(),
            data_: e.data,
            aad_: e.aad,
            sender_index_: e.sender_index,
            epoch_: e.epoch,
            removed_: e.removed,
        }
    }
}

#[pymethods]
impl Event {
    /// `"application"`, `"commit"`, `"proposal"` or `"other"`.
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind_
    }
    /// Decrypted application data (`application` events only).
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.data_.as_deref().map(|d| PyBytes::new(py, d))
    }
    /// Authenticated, *not encrypted*, data sent with the message.
    #[getter]
    fn aad<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.aad_)
    }
    /// Sender's leaf index (None for non-member senders). Not an identity.
    #[getter]
    fn sender_index(&self) -> Option<u32> {
        self.sender_index_
    }
    /// Epoch after processing.
    #[getter]
    fn epoch(&self) -> u64 {
        self.epoch_
    }
    /// True if this commit removed us; the group is now terminal.
    #[getter]
    fn removed(&self) -> bool {
        self.removed_
    }
    /// Never includes plaintext or aad contents.
    fn __repr__(&self) -> String {
        format!(
            "Event(kind={:?}, data_len={}, aad_len={}, sender_index={}, epoch={}, removed={})",
            self.kind_,
            self.data_
                .as_ref()
                .map_or("None".to_string(), |d| d.len().to_string()),
            self.aad_.len(),
            self.sender_index_
                .map_or("None".to_string(), |i| i.to_string()),
            self.epoch_,
            if self.removed_ { "True" } else { "False" },
        )
    }
}

#[pymodule]
fn _mls_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Client>()?;
    m.add_class::<Group>()?;
    m.add_class::<Event>()?;
    m.add("MlsError", py.get_type::<MlsError>())?;
    m.add(
        "SUPPORTED_CIPHER_SUITES",
        PyTuple::new(py, facade::SUPPORTED_CIPHER_SUITES)?,
    )?;
    m.add("DEFAULT_CIPHER_SUITE", facade::DEFAULT_CIPHER_SUITE)?;
    m.add("DEFAULT_MAX_MESSAGE_SIZE", facade::DEFAULT_MAX_MESSAGE_SIZE)?;
    m.add(
        "ERROR_CODES",
        PyTuple::new(py, facade::ErrorCode::ALL.iter().map(|c| c.as_str()))?,
    )?;
    Ok(())
}
