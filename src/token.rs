use std::ptr;

use nss_sys::{C_CloseSession, C_OpenSession, CKF_SERIAL_SESSION, CKR_OK, CK_SESSION_HANDLE};

#[derive(Debug)]
pub enum Error {
    UnableToOpenSession,
}

pub struct TokenSession {
    pub(crate) session: CK_SESSION_HANDLE,
}

impl TokenSession {
    pub fn new() -> Result<Self, Error> {
        let session = ptr::null_mut();
        let app = ptr::null_mut();
        let status = unsafe { C_OpenSession(1, CKF_SERIAL_SESSION, app, None, session) };

        let session = if status == CKR_OK {
            unsafe { *session }
        } else {
            return Err(Error::UnableToOpenSession);
        };

        Ok(TokenSession { session })
    }
}

impl Drop for TokenSession {
    fn drop(&mut self) {
        unsafe {
            C_CloseSession(self.session);
        }
    }
}

impl PartialEq for TokenSession {
    fn eq(&self, other: &Self) -> bool {
        self.session == other.session
    }
}
