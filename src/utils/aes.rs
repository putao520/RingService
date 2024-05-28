use aead::consts::U12;
use aead::{Aead, Nonce};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, KeyInit};
use anyhow::Result;
use chrono::Utc;
use crypto::common::Key;
use once_cell::sync::Lazy;
use sha2::Digest;
use sha2::Sha256;

pub struct AesCoder {
    // key: Key<Aes256Gcm>,
    nonce: Nonce<AesGcm<Aes256, U12>>,
    cipher: AesGcm<Aes256, U12>,
}

fn generate_nonce_from_key(key: &[u8; 32]) -> Nonce<AesGcm<Aes256, U12>> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    let nonce_bytes = &result[0..12];
    *Nonce::<AesGcm<Aes256, U12>>::from_slice(nonce_bytes)
}
impl AesCoder {
    pub fn new(key: &[u8; 32]) -> Self {
        let nonce = generate_nonce_from_key(key);
        let key = *Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);
        Self { nonce, cipher }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // utc 时区当前时间戳
        let now = Utc::now();
        let timestamp = now.timestamp();
        // timestamp 转成 Vec<u8> 类型 再把 data 附加到后面
        let mut packet_data = timestamp.to_be_bytes().to_vec();
        packet_data.extend_from_slice(data);
        match self.cipher.encrypt(&self.nonce, packet_data.as_slice()) {
            Ok(cipher_text) => Ok(cipher_text),
            Err(e) => Err(anyhow::anyhow!("Failed to encrypt data: {:?}", e)),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.cipher.decrypt(&self.nonce, data) {
            Ok(plain_text) => {
                let timestamp = i64::from_be_bytes([
                    plain_text[0],
                    plain_text[1],
                    plain_text[2],
                    plain_text[3],
                    plain_text[4],
                    plain_text[5],
                    plain_text[6],
                    plain_text[7],
                ]);
                let now = Utc::now();
                let now_timestamp = now.timestamp();
                if now_timestamp - timestamp > 5 {
                    return Err(anyhow::anyhow!("Data is expired"));
                }
                Ok(plain_text[8..].to_vec())
            }
            Err(e) => Err(anyhow::anyhow!("Failed to decrypt data: {:?}", e)),
        }
    }
}

static AES_SHARE_KEY: &[u8] = b"ptu#h1$!@$AH!@#$YUF@!~asdo1`421o";
pub static AES_CODER: Lazy<AesCoder> =
    Lazy::new(|| AesCoder::new(<&[u8; 32]>::try_from(AES_SHARE_KEY).unwrap()));
pub fn decode_domain(sec_domain: &[u8]) -> anyhow::Result<String> {
    let u8_arr = AES_CODER.decrypt(sec_domain)?;
    Ok(String::from_utf8(u8_arr)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes_coder() {
        let domain = "www.baidu.com";
        let sec = AES_CODER.encrypt(domain.as_bytes()).unwrap();
        let d_domain = decode_domain(&sec).unwrap();

        println!("domain={}", d_domain);
        assert_eq!(domain, d_domain);
    }
}
