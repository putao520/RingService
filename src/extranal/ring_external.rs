#![allow(non_snake_case)]
#[cfg(windows)]
#[link(name = "RingExtranal", kind = "static")]
extern "C" {
    pub fn DnsFlushResolverCache();

    pub fn QueryDnsIPV4(domain: *const u8, doh_server: *const u8) -> u32;

    pub fn StartPacProxy(pac_url: *const u8, proxy_peer: *const u8);

    pub fn StopPacProxy();

    pub fn GetPacFunction() -> *const u8;

    pub fn FreePacFunction(pac_function: *const u8);

    pub fn StartSystemProxy(proxy_peer: *const u8);

    pub fn StopSystemProxy();
}
