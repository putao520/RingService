use anyhow::Result;
use rand::Rng;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

pub fn generate_random_string(length: u32) -> String {
    let mut rng = rand::thread_rng();
    let mut result = String::new();
    for _ in 0..length {
        let c = rng.gen_range(0..=9);
        result.push_str(c.to_string().as_str());
    }
    result
}

#[cfg(windows)]
pub fn str_to_pcwstr(s: &str) -> Vec<u16> {
    let os_str: &OsStr = s.as_ref();
    let mut wide_string: Vec<u16> = os_str.encode_wide().collect();
    wide_string.push(0); // Add null terminator
    wide_string
}

pub fn ipv4_to_u32(ip: &str) -> Result<u32> {
    let addr = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(addr))
}
