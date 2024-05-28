use std::sync::Arc;

use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::utils::aes::AES_CODER;
use crate::utils::u32_sec::xor_u32;

static DNS_CACHE: Lazy<DashMap<String, u32>> = Lazy::new(|| DashMap::new());

// dog -H @https://pure-dns.gscyun.com/dns-query www.pixivision.net

// static DNS_SERVER: &[u8] = b"https://pure-dns.gscyun.com/dns-query\0";
// pub fn query_dns_ipv4(host: &str) -> u32 {
//     if DNS_CACHE.contains_key(host) {
//         return *DNS_CACHE.get(host).unwrap().value();
//     }
//     let c_host = CString::new(host).unwrap();
//     let ip = unsafe { QueryDnsIPV4(c_host.as_ptr() as *const u8, DNS_SERVER.as_ptr()) };
//     if ip != 0 {
//         DNS_CACHE.insert(host.to_string(), ip);
//     }
//     ip
// }

#[cfg(not(debug_assertions))]
static DNS_LOCAL_SERVER: &str = "https://dns.gscyun.com/q";

#[cfg(debug_assertions)]
// static DNS_LOCAL_SERVER: &str = "http://127.0.0.1:8080/q";
static DNS_LOCAL_SERVER: &str = "https://dns.gscyun.com/q";
static DNS_CLIENT: Lazy<Arc<reqwest::Client>> = Lazy::new(|| Arc::new(reqwest::Client::new()));
pub async fn query_local_dns(host: &str) -> anyhow::Result<u32> {
    let sec_domain = AES_CODER.encrypt(host.as_bytes()).unwrap();
    if DNS_CACHE.contains_key(host) {
        return Ok(*DNS_CACHE.get(host).unwrap().value());
    }

    let cli = Arc::clone(&DNS_CLIENT);
    let res = cli
        .post(DNS_LOCAL_SERVER)
        .header("Content-Type", "application/x-memory-gateway")
        .body(sec_domain)
        .send()
        .await?;

    if res.status() != 200 {
        return Err(anyhow::anyhow!("Failed to query local dns"));
    }

    let body = res.text().await?;

    let ip_no = xor_u32(body.parse::<u32>()?);

    if ip_no != 0 {
        DNS_CACHE.insert(host.to_string(), ip_no);
    }

    Ok(ip_no)
}

#[cfg(test)]
mod tests {
    use crate::utils::aes::AES_CODER;
    use crate::utils::u32_sec::xor_u32;

    use super::*;

    #[tokio::test]
    async fn test_local_dns() {
        let sec_domain = AES_CODER.encrypt(b"oauth.secure.pixiv.net").unwrap();

        let client = reqwest::Client::new();
        let res = client
            .post("http://127.0.0.1:8080/q")
            .header("Content-Type", "application/x-memory-gateway")
            .body(sec_domain)
            .send()
            .await
            .unwrap();

        println!("Status: {}", res.status());

        let body = res.text().await.unwrap();

        let ip = xor_u32(body.parse::<u32>().unwrap());

        println!("Body:\n\n{}->{}", body, ip);
    }

    #[tokio::test]
    async fn test_remote_dns() {
        let sec_domain = AES_CODER.encrypt(b"github.com").unwrap();

        let client = reqwest::Client::new();
        let res = client
            .post("https://dns.gscyun.com/q")
            .header("Content-Type", "application/x-memory-gateway")
            .body(sec_domain)
            .send()
            .await
            .unwrap();

        println!("Status: {}", res.status());

        let body = res.text().await.unwrap();

        let ip = xor_u32(body.parse::<u32>().unwrap());

        println!("Body:\n\n{}->{}", body, ip);
    }
}
