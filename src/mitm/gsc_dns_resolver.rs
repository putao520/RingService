use crate::utils::aes::AES_CODER;
use crate::utils::strings::print_ip;
use crate::utils::u32_sec::xor_u32;
use anyhow::Result;
use dashmap::DashMap;
use futures_util::future;
use merge_executers::MergeExecutes;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;

#[derive(Serialize, Deserialize, Debug)]
struct Question {
    name: String,
    #[serde(rename = "type")]
    query_type: u8,
}
#[derive(Serialize, Deserialize, Debug)]
struct Answer {
    name: String,
    #[serde(rename = "type")]
    answer_type: u8,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: u8,
    #[serde(rename = "TC")]
    tc: bool,
    #[serde(rename = "RD")]
    rd: bool,
    #[serde(rename = "RA")]
    ra: bool,
    #[serde(rename = "AD")]
    ad: bool,
    #[serde(rename = "CD")]
    cd: bool,
    #[serde(rename = "Question")]
    question: Vec<Question>,
    #[serde(rename = "Answer")]
    answer: Vec<Answer>,
}

static REGION_RULE: Lazy<RwLock<Vec<String>>> = Lazy::new(|| RwLock::new(Vec::new()));
static DNS_CACHE: Lazy<DashMap<String, u32>> = Lazy::new(|| DashMap::new());
// static DNS_LOCAL_SERVER: &str = "https://pure-dns.gscyun.com/q";
static DNS_LOCAL_SERVER: &str = "http://127.0.0.1:8080/q";
static DNS_CLIENT: Lazy<Arc<reqwest::Client>> = Lazy::new(|| Arc::new(reqwest::Client::new()));
// 归并执行器
static MERGER_EXECUTE: Lazy<MergeExecutes<u32>> = Lazy::new(|| MergeExecutes::new());

async fn test_https_ip(ip: u32) -> Result<u32, std::io::Error> {
    let socket_addrs = SocketAddrV4::new(Ipv4Addr::from(ip), 443);
    let connect_future = TcpStream::connect(socket_addrs);
    let timeout_duration = Duration::from_secs(5);

    match timeout(timeout_duration, connect_future).await {
        Ok(_) => Ok(ip),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Connection timed out",
        )),
    }
}

pub async fn query_gsc_dns(host: &str) -> Result<u32> {
    if DNS_CACHE.contains_key(host) {
        return Ok(*DNS_CACHE.get(host).unwrap().value());
    }
    MERGER_EXECUTE
        .run_task(host, async {
            match query_local_dns_impl(host).await {
                Ok(ip) => Ok(ip),
                Err(_) => Ok(0),
            }
        })
        .await
}
async fn query_local_dns_impl(host: &str) -> Result<u32> {
    let sec_domain = AES_CODER.encrypt(host.as_bytes()).unwrap();

    let cli = Arc::clone(&DNS_CLIENT);
    let mut ip_no = 0;
    let region_ref = REGION_RULE.read().await;
    for region_key in region_ref.iter() {
        // println!("region_key={}", region_key);
        let dns_url = format!("{}?region={}", DNS_LOCAL_SERVER, region_key.as_str());
        let res = cli
            .post(dns_url)
            .header("Content-Type", "application/x-memory-gateway")
            .body(sec_domain.clone())
            .send()
            .await
            .unwrap();
        if res.status() != 200 {
            return Err(anyhow::anyhow!("Failed to query local dns"));
        }
        let body = res.text().await.unwrap();
        let body: Vec<u32> = body
            .split(",")
            .map(|s| u32::from_str_radix(s, 16).unwrap())
            .collect();
        let mut test_handlers = vec![];
        for ip in body {
            test_handlers.push(Box::pin(test_https_ip(ip)));
        }
        if let Ok((result, _remaining_futures)) = future::select_ok(test_handlers).await {
            ip_no = result;
            break;
        }
    }
    if ip_no != 0 {
        ip_no = xor_u32(ip_no);
        DNS_CACHE.insert(host.to_string(), ip_no);
    }
    #[cfg(debug_assertions)]
    println!("DNS: {}->{}", host, print_ip(ip_no));
    Ok(ip_no)
}

pub async fn refresh_region(region: &str) -> Result<()> {
    let region_array: Vec<String> = serde_yaml::from_str(region)?;
    let mut desc = REGION_RULE.write().await;
    desc.clear();
    for it in region_array.iter() {
        desc.push(it.clone());
    }
    Ok(())
}

pub async fn load_test_region() -> Result<()> {
    let region = fs::read_to_string("test_region.yaml").await?;
    refresh_region(region.as_str()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_query_local_dns() {
        load_test_region().await.unwrap();
        let host = "www.baidu.com";
        let mut handle_arr = vec![];
        for _ in 0..100 {
            handle_arr.push(Box::pin(query_gsc_dns(host)));
        }
        let mut ip_no = 0;
        let (r, i, v) = future::select_all(handle_arr).await;
        if let Ok(ip) = r {
            ip_no = ip;
        }
        println!("{}->{}", host, print_ip(ip_no));
    }

    #[tokio::test]
    async fn test_multi_query_local_dns() {
        load_test_region().await.unwrap();
        let host = "www.baidu.com";
        for i in 0..5 {
            println!("{}->", i);
            let ip_no = query_gsc_dns(host).await.unwrap();
            println!("{}->{}", i, print_ip(ip_no));
        }
    }
}
