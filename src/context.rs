use std::ptr;

use nss_sys::nspr::PR_TRUE;
use nss_sys::{
    NSSInitContext, NSS_InitContext, NSS_IsInitialized, NSS_ShutdownContext, NSS_INIT_NOCERTDB,
    NSS_INIT_NOMODDB, NSS_INIT_NOROOTINIT, NSS_INIT_PK11RELOAD,
};

#[derive(Debug)]
pub enum Error {
    UnableToOpenContext,
}

pub struct Context {
    context: Option<*mut NSSInitContext>,
}

impl Context {
    pub fn new() -> Result<Self, Error> {
        crate::nspr::init();
        // nss does not play well if initialized with context after being
        // initialized without
        if unsafe { NSS_IsInitialized() } == PR_TRUE {
            Ok(Context { context: None })
        } else {
            let context = unsafe {
                NSS_InitContext(
                    ptr::null(),     // configdir
                    ptr::null(),     // certprefix
                    ptr::null(),     // keyprefix
                    ptr::null(),     // secmodname
                    ptr::null_mut(), // init params
                    NSS_INIT_NOROOTINIT
                        | NSS_INIT_NOCERTDB
                        | NSS_INIT_NOMODDB
                        | NSS_INIT_PK11RELOAD, // flags
                )
            };

            if !context.is_null() {
                Ok(Context {
                    context: Some(context),
                })
            } else {
                Err(Error::UnableToOpenContext)
            }
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            unsafe { NSS_ShutdownContext(context) };
        }
    }
}
