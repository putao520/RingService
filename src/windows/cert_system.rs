use std::path::Path;
use std::ptr::null_mut;

use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509NameBuilder, X509};
use rand::rngs::OsRng;
use rand::Rng;
use tokio::fs;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, PFXImportCertStore,
    CERT_CONTEXT, CERT_FIND_ANY, CRYPT_INTEGER_BLOB, CRYPT_MACHINE_KEYSET,
    CRYPT_MESSAGE_SILENT_KEYSET_FLAG, CRYPT_SILENT, HCERTSTORE, X509_ASN_ENCODING,
};

use crate::mitm::machine_id::get_machine_id;
use crate::utils::strings::str_to_pcwstr;
use crate::windows::cert_manager::CertLocalSystem;

pub async fn get_pfx_path(password: &str) -> Result<String> {
    if !Path::new("root_ca").exists() {
        // 创建 root_ca 文件夹
        fs::create_dir("root_ca").await?;
    }

    let pfx_path = "root_ca/cert.pfx".to_string();
    if !Path::new(pfx_path.as_str()).exists() {
        let (cert_pem, key_pem) = generate_root_ca()?;

        let pfx_root = convert_to_pkcs12(cert_pem.as_slice(), key_pem.as_slice(), password)?;

        fs::write(pfx_path.as_str(), pfx_root.clone()).await?;
    }
    return Ok(pfx_path);
}

pub fn generate_root_ca() -> Result<(Vec<u8>, Vec<u8>)> {
    // 生成RSA密钥对
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    // 创建X509名字构建器
    let mut x509_name = X509NameBuilder::new().unwrap();

    // 添加国家
    x509_name
        .append_entry_by_nid(Nid::COUNTRYNAME, "CN")
        .unwrap();
    // 添加组织
    x509_name
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "BeyondDimension")
        .unwrap();
    // 添加组织单位
    x509_name
        .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Technical Department")
        .unwrap();
    // 添加通用名
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, "RingSpace Certificate")
        .unwrap();

    // 创建X509名字
    let x509_name = x509_name.build();

    // 创建X509构建器
    let mut x509_builder = X509::builder().unwrap();

    // 设置证书为CA证书
    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    x509_builder.append_extension(basic_constraints).unwrap();
    // 设置密钥用途
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    x509_builder.append_extension(key_usage).unwrap();

    // 设置扩展密钥用途
    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()
        .unwrap();
    x509_builder.append_extension(ext_key_usage).unwrap();

    // 设置序列号
    let mut rng = OsRng;
    let random_bytes: [u8; 16] = rng.gen(); // 16 bytes = 32 hexadecimal digits
    let hex_string = hex::encode(random_bytes);
    let serial_number = BigNum::from_hex_str(&hex_string)
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    x509_builder.set_serial_number(&serial_number).unwrap();

    // 设置主题名
    x509_builder.set_subject_name(&x509_name).unwrap();

    // 设置颁发者名
    x509_builder.set_issuer_name(&x509_name).unwrap();

    // 设置有效期
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    x509_builder.set_not_before(&not_before).unwrap();
    x509_builder.set_not_after(&not_after).unwrap();

    // 设置公钥
    x509_builder.set_pubkey(&pkey).unwrap();

    // 使用私钥签名证书
    x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    // 构建X509证书
    let x509 = x509_builder.build();

    // 将私钥和证书转换为PEM格式
    let private_key_pem = pkey.private_key_to_pem_pkcs8()?;
    let certificate_pem = x509.to_pem()?;

    Ok((certificate_pem, private_key_pem))
}

pub fn convert_to_pkcs12(cert_pem: &[u8], key_pem: &[u8], password: &str) -> Result<Vec<u8>> {
    let cert = X509::from_pem(cert_pem)?;
    let key = PKey::from_rsa(Rsa::private_key_from_pem(&key_pem)?)?;
    // 生成PFX
    let pfx = Pkcs12::builder()
        .cert(cert.as_ref())
        .pkey(key.as_ref())
        .build2(password)?;
    Ok(pfx.to_der()?)
}

pub struct CertSystem {
    pub h_cert_store: HCERTSTORE,
    pub pfx_root: Vec<u8>,
    pub cert_ctx: *mut CERT_CONTEXT,
    pub password: String,
    cls: CertLocalSystem,
}

impl Drop for CertSystem {
    fn drop(&mut self) {
        unsafe {
            if !self.cert_ctx.is_null() {
                // 关闭证书上下文
                CertFreeCertificateContext(self.cert_ctx);
            }
            if !self.h_cert_store.is_null() {
                // 关闭证书存储区
                CertCloseStore(self.h_cert_store, 0);
            }
        }
    }
}

async fn pem_parse_pfx(pfx_root: &[u8], password: &str) -> Result<(String, String)> {
    // 解析 pfx
    let pfx = Pkcs12::from_der(pfx_root)?;
    let pfx = pfx.parse2(password)?;
    let pkey = pfx.pkey.unwrap().private_key_to_pem_pkcs8()?;
    let cert = pfx.cert.unwrap().to_pem()?;

    Ok((String::from_utf8(cert)?, String::from_utf8(pkey)?))
}

async fn der_parse_pfx(pfx_root: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    // 解析 pfx
    let pfx = Pkcs12::from_der(pfx_root)?;
    let pfx = pfx.parse2(password)?;
    let pkey = pfx.pkey.unwrap().private_key_to_der()?;
    let cert = pfx.cert.unwrap().to_der()?;

    Ok((cert, pkey))
}

async fn build_ca_pem(
    replace: bool,
    password: &str,
) -> Result<(Vec<u8>, HCERTSTORE, *mut CERT_CONTEXT)> {
    let pfx_root = CertSystem::regenerate_ca(replace, password).await?;
    Ok(unsafe {
        let crypt_data_blob = CRYPT_INTEGER_BLOB {
            cbData: pfx_root.len() as u32,
            pbData: pfx_root.as_ptr() as *mut u8,
        };
        let password = str_to_pcwstr(password);
        let hc = PFXImportCertStore(
            &crypt_data_blob,
            password.as_ptr(),
            CRYPT_SILENT | CRYPT_MACHINE_KEYSET | CRYPT_MESSAGE_SILENT_KEYSET_FLAG,
        );
        if hc.is_null() {
            let err = GetLastError();
            return Err(anyhow::anyhow!(
                "Failed to import certificate store with error code: {}",
                err
            ));
        }
        let mut p_context = null_mut();
        p_context = CertFindCertificateInStore(
            hc,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            null_mut(),
            p_context,
        );
        if p_context.is_null() {
            let err = GetLastError();
            return Err(anyhow::anyhow!(
                "Failed to find certificate context with error code: {}",
                err
            ));
        }
        (pfx_root, hc, p_context)
    })
}

impl CertSystem {
    pub async fn new() -> Result<Self> {
        let password = get_machine_id();
        let (pfx_root, h_cert_store, cert_ctx) = build_ca_pem(false, password.as_str()).await?;

        unsafe {
            Ok(CertSystem {
                h_cert_store,
                password,
                pfx_root,
                cert_ctx,
                cls: CertLocalSystem::new(),
            })
        }
    }

    pub async fn regenerate_ca(replace: bool, password: &str) -> Result<(Vec<u8>)> {
        // 判断 root_ca 文件夹是否存在
        if !Path::new("root_ca").exists() {
            // 创建 root_ca 文件夹
            fs::create_dir("root_ca").await?;
        }

        let pfx_path = format!("root_ca/cert_{}.pfx", password);
        if Path::new(pfx_path.as_str()).exists() {
            if replace == true {
                let _ = fs::remove_file(pfx_path.as_str()).await;
            } else {
                let cert = fs::read(pfx_path.as_str()).await?;
                return Ok(cert);
            }
        }
        let (cert_pem, key_pem) = generate_root_ca()?;

        let pfx_root = convert_to_pkcs12(cert_pem.as_slice(), key_pem.as_slice(), password)?;

        fs::write(pfx_path.as_str(), pfx_root.clone()).await?;

        Ok(pfx_root)
    }
    pub fn verify_ca(&mut self) -> bool {
        self.cls.load_cert(self.cert_ctx);
        self.cls.verify()
    }

    pub fn store_ca(&self) -> bool {
        self.cls.add(self.cert_ctx)
    }

    pub fn remove_ca(&mut self) -> bool {
        self.cls.load_cert(self.cert_ctx);
        self.cls.remove()
    }

    pub fn print_ca(&self) {
        self.cls.print()
    }

    pub async fn get_cert_pem(&self) -> Result<(String, String)> {
        pem_parse_pfx(self.pfx_root.as_slice(), self.password.as_str()).await
    }
}

pub async fn test_root_ca() {
    let mut root_ca = match CertSystem::new().await {
        Ok(ca) => ca,
        Err(result) => {
            println!("Create root ca failed,{}", result);
            return;
        }
    };

    // 导入系统库
    root_ca.store_ca();

    // 延迟 10 秒
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // 删除系统库
    root_ca.remove_ca();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_root_ca() {
        test_root_ca().await;

        assert!(true)
    }
}
