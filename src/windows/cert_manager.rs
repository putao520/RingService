use std::ffi::{c_void, CStr};
use std::ptr::null_mut;

use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Security::Cryptography::{
    CertAddCertificateContextToStore, CertCloseStore, CertDeleteCertificateFromStore,
    CertFindCertificateInStore, CertFreeCertificateContext, CertNameToStrA, CertOpenStore,
    CertVerifyTimeValidity, CERT_CONTEXT, CERT_FIND_ANY, CERT_FIND_EXISTING, CERT_SIMPLE_NAME_STR,
    CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, CERT_STORE_PROV_SYSTEM, HCERTSTORE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

use crate::utils::strings::str_to_pcwstr;

pub const CERT_SYSTEM_STORE_LOCAL_MACHINE: u32 = 131072u32;
pub const CERT_STORE_CLOSE_FORCE_FLAG: u32 = 1u32;
pub struct CertLocalSystem {
    pub store: HCERTSTORE,
    load_cert_ctx: *mut CERT_CONTEXT,
    current_cert_ctx: *mut CERT_CONTEXT,
}

impl CertLocalSystem {
    pub fn new() -> Self {
        let store_name = str_to_pcwstr("Root");
        unsafe {
            CertLocalSystem {
                store: CertOpenStore(
                    CERT_STORE_PROV_SYSTEM as PCSTR,
                    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                    0,
                    CERT_SYSTEM_STORE_LOCAL_MACHINE | 0x1,
                    store_name.as_ptr() as *mut c_void,
                ),
                load_cert_ctx: null_mut(),
                current_cert_ctx: null_mut(),
            }
        }
    }

    pub fn load_cert(&mut self, cert_ctx: *mut CERT_CONTEXT) {
        if !self.current_cert_ctx.is_null() {
            unsafe {
                CertFreeCertificateContext(self.current_cert_ctx);
            }
            self.current_cert_ctx = null_mut();
        }
        self.load_cert_ctx = cert_ctx;
        let mut p_find_context = self.find_cert();
        if p_find_context.is_null() {
            return;
        }
        self.current_cert_ctx = p_find_context;
    }

    fn find_cert(&self) -> *mut CERT_CONTEXT {
        unsafe {
            CertFindCertificateInStore(
                self.store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_EXISTING,
                self.load_cert_ctx as *mut c_void,
                null_mut(),
            )
        }
    }

    pub fn add(&self, cert_context: *mut CERT_CONTEXT) -> bool {
        let result = unsafe {
            CertAddCertificateContextToStore(
                self.store,
                cert_context,
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                null_mut(),
            )
        };

        if result == FALSE {
            let err = std::io::Error::last_os_error();
            println!(
                "Failed to add certificate context to store with error code: {}",
                err
            );
            return false;
        }
        true
    }

    pub fn verify(&self) -> bool {
        if self.current_cert_ctx.is_null() {
            return false;
        }
        if unsafe { CertVerifyTimeValidity(null_mut(), (*self.current_cert_ctx).pCertInfo) } == 0 {
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self) -> bool {
        if self.load_cert_ctx.is_null() {
            println!("No certificate context to remove");
            return false;
        }

        if !self.current_cert_ctx.is_null() {
            unsafe {
                CertDeleteCertificateFromStore(self.current_cert_ctx);
            }
            self.current_cert_ctx = null_mut();
        }

        loop {
            let p_find_context = self.find_cert();
            if p_find_context.is_null() {
                break;
            }
            unsafe {
                if CertDeleteCertificateFromStore(p_find_context) == FALSE {
                    let err = std::io::Error::last_os_error();
                    println!(
                        "Failed to delete certificate context from store with error code: {}",
                        err
                    );
                    return false;
                }
            }
        }

        true
    }

    pub fn print(&self) {
        let mut p_context = null_mut();
        loop {
            p_context = unsafe {
                CertFindCertificateInStore(
                    self.store,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_ANY,
                    null_mut(),
                    p_context,
                )
            };
            unsafe {
                if p_context.is_null() {
                    break;
                }
            }
            let mut issuer: [i8; 512] = [0; 512];
            unsafe {
                CertNameToStrA(
                    (*p_context).dwCertEncodingType,
                    &mut (*(*p_context).pCertInfo).Issuer,
                    CERT_SIMPLE_NAME_STR,
                    issuer.as_mut_ptr() as *mut u8,
                    512,
                );
            }
            let issuer_name = unsafe {
                CStr::from_ptr(issuer.as_ptr())
                    .to_str()
                    .unwrap_or_else(|_| "Invalid UTF-8 sequence")
            };
            println!("{}", issuer_name);
        }
    }
}

impl Drop for CertLocalSystem {
    fn drop(&mut self) {
        if !self.current_cert_ctx.is_null() {
            unsafe {
                CertFreeCertificateContext(self.current_cert_ctx);
            }
        }
        if !self.store.is_null() {
            unsafe {
                CertCloseStore(self.store, CERT_STORE_CLOSE_FORCE_FLAG);
            }
        }
    }
}
