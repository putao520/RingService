use std::error::Error;
use std::ffi::CString;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{self, Poll};
use std::{fmt, io, vec};

use hudsucker::hyper_util::client::legacy::connect::dns::Name;
use tokio::task::JoinHandle;
use tower_service::Service;

use crate::extranal::ring_external::QueryDnsIPV4;
use crate::mitm::dns_resolver::query_local_dns;

/// A resolver using blocking `getaddrinfo` calls in a threadpool.
#[derive(Clone)]
pub struct RingResolver {
    _priv: (),
}

/// An iterator of IP addresses returned from `getaddrinfo`.
pub struct GaiAddrs {
    inner: SocketAddrs,
}

/// A future to resolve a name returned by `RingResolver`.
pub struct RingFuture {
    inner: JoinHandle<Result<SocketAddrs, io::Error>>,
}

impl RingResolver {
    /// Construct a new `RingResolver`.
    pub fn new() -> Self {
        RingResolver { _priv: () }
    }
}

async fn dns_local_impl(host: String) -> Result<SocketAddrs, io::Error> {
    match query_local_dns(host.as_str()).await {
        Ok(ip_num) => {
            if ip_num == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "QueryDnsIPV4 failed"));
            }
            let ip_addr = Ipv4Addr::from(ip_num);
            let ip_arr = vec![SocketAddr::new(IpAddr::V4(ip_addr), 0)];
            Ok(SocketAddrs::new(ip_arr))
        }
        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "QueryDnsIPV4 failed")),
    }
}

// fn dns_impl(host: &str) -> Result<SocketAddrs, io::Error> {
//     let ip_num = filter_dns_by_rules(host);
//     if (ip_num == 0) {
//         println!("QueryDnsIPV4 failed");
//         return Err(io::Error::new(io::ErrorKind::Other, "QueryDnsIPV4 failed"));
//     }
//     let ip_addr = IpAddr::V4(Ipv4Addr::from(ip_num));
//     let ip_arr = vec![SocketAddr::new(ip_addr, 0)];
//     Ok(SocketAddrs::new(ip_arr))
// }

impl Service<Name> for RingResolver {
    type Response = GaiAddrs;
    type Error = io::Error;
    type Future = RingFuture;
    // type Future = Pin<Box<dyn Future<Output = Result<SocketAddrs, io::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        // let blocking = tokio::task::spawn_blocking(move || {
        //     let host = name.as_str();
        //     debug!("resolving host={:?}", host);
        //     dns_impl(host)
        // });

        let blocking = tokio::task::spawn(dns_local_impl(name.to_string()));
        RingFuture { inner: blocking }
        // let a = dns_local_impl(name.as_str())
    }
}

impl fmt::Debug for RingResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("RingResolver")
    }
}

impl Future for RingFuture {
    type Output = Result<GaiAddrs, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(|res| match res {
            Ok(Ok(addrs)) => Ok(GaiAddrs { inner: addrs }),
            Ok(Err(err)) => Err(err),
            Err(join_err) => {
                if join_err.is_cancelled() {
                    Err(io::Error::new(io::ErrorKind::Interrupted, join_err))
                } else {
                    panic!("gai background task failed: {:?}", join_err)
                }
            }
        })
    }
}

impl fmt::Debug for RingFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("RingFuture")
    }
}

impl Drop for RingFuture {
    fn drop(&mut self) {
        self.inner.abort();
    }
}

impl Iterator for GaiAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl fmt::Debug for GaiAddrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("GaiAddrs")
    }
}

pub(super) struct SocketAddrs {
    iter: vec::IntoIter<SocketAddr>,
}

impl SocketAddrs {
    pub(super) fn new(addrs: Vec<SocketAddr>) -> Self {
        SocketAddrs {
            iter: addrs.into_iter(),
        }
    }

    pub(super) fn try_parse(host: &str, port: u16) -> Option<SocketAddrs> {
        if let Ok(addr) = host.parse::<Ipv4Addr>() {
            let addr = SocketAddrV4::new(addr, port);
            return Some(SocketAddrs {
                iter: vec![SocketAddr::V4(addr)].into_iter(),
            });
        }
        if let Ok(addr) = host.parse::<Ipv6Addr>() {
            let addr = SocketAddrV6::new(addr, port, 0, 0);
            return Some(SocketAddrs {
                iter: vec![SocketAddr::V6(addr)].into_iter(),
            });
        }
        None
    }

    #[inline]
    fn filter(self, predicate: impl FnMut(&SocketAddr) -> bool) -> SocketAddrs {
        SocketAddrs::new(self.iter.filter(predicate).collect())
    }

    pub(super) fn split_by_preference(
        self,
        local_addr_ipv4: Option<Ipv4Addr>,
        local_addr_ipv6: Option<Ipv6Addr>,
    ) -> (SocketAddrs, SocketAddrs) {
        match (local_addr_ipv4, local_addr_ipv6) {
            (Some(_), None) => (self.filter(SocketAddr::is_ipv4), SocketAddrs::new(vec![])),
            (None, Some(_)) => (self.filter(SocketAddr::is_ipv6), SocketAddrs::new(vec![])),
            _ => {
                let preferring_v6 = self
                    .iter
                    .as_slice()
                    .first()
                    .map(SocketAddr::is_ipv6)
                    .unwrap_or(false);

                let (preferred, fallback) = self
                    .iter
                    .partition::<Vec<_>, _>(|addr| addr.is_ipv6() == preferring_v6);

                (SocketAddrs::new(preferred), SocketAddrs::new(fallback))
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.iter.as_slice().is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.iter.as_slice().len()
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;
    #[inline]
    fn next(&mut self) -> Option<SocketAddr> {
        self.iter.next()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use crate::extranal::ring_external::QueryDnsIPV4;

    use super::*;

    #[test]
    fn test_dns() {
        let host = "www.baidu.com.";
        println!("resolving host={:?}", host);

        let domain = CString::new("www.baidu.com").unwrap();
        // https://dns.alidns.com/dns-query
        let ip_num = unsafe {
            QueryDnsIPV4(
                domain.as_ptr() as *const u8,
                b"https://dns.alidns.com/dns-query\0".as_ptr(),
            )
        };
        if (ip_num == 0) {
            println!("QueryDnsIPV4 failed");
            return;
        }

        let ip_addr = Ipv4Addr::from(ip_num);
        println!("ip: {:?}", ip_addr.to_string());

        assert!(true);
    }
}
