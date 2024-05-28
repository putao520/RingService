use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Mutex;

use anyhow::Result;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::fs;

use crate::utils::strings::ipv4_to_u32;

#[derive(Serialize, Deserialize, Clone)]
pub struct FilterFlowDesc {
    pub nsfw: Option<u32>, // nsfw 过滤
    pub rules: Option<DashMap<String, Option<FilterFlowDesc>>>,
    pub paths: Option<DashMap<String, Option<FilterFlowDesc>>>,
    #[serde(rename = "p")]
    pub proxy: Option<String>, // 代理服务器 替换
    #[serde(rename = "s")]
    pub sni: Option<String>, // sni 替换
    #[serde(rename = "h")]
    pub host: Option<String>, // host 替换
    #[serde(
        rename = "r4",
        default,
        serialize_with = "serialize_redirect_v4",
        deserialize_with = "deserialize_redirect_v4"
    )]
    pub redirect_v4: Option<u32>, // 重定向
}

impl FilterFlowDesc {
    pub fn default() -> Self {
        FilterFlowDesc {
            nsfw: Some(0u32),
            proxy: None,
            rules: None,
            paths: None,
            redirect_v4: None,
            sni: None,
            host: None,
        }
    }
}

fn serialize_redirect_v4<S>(
    redirect_v4: &Option<u32>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = match redirect_v4 {
        Some(v) => Ipv4Addr::from(*v).to_string(),
        None => "127.0.0.1".to_string(),
    };
    serializer.serialize_str(&s)
}

fn deserialize_redirect_v4<'de, D>(deserializer: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer) {
        Ok(d_s) => match d_s {
            None => Ok(None),
            Some(s) => {
                if s.is_empty() {
                    return Ok(None);
                }
                match ipv4_to_u32(s.as_str()) {
                    Ok(v) => return Ok(Some(v)),
                    Err(_) => Ok(None),
                }
            }
        },
        Err(_) => Ok(None),
    }
}

type FilterFlowDescMap = DashMap<String, Option<FilterFlowDesc>>;
pub static SHARE_FILTER_FLOW_DESC: Lazy<FilterFlowDescMap> = Lazy::new(|| DashMap::new());

static REPLACE_RULES_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(())); // 完整替换规则锁

fn refresh_filter_flow(rules_str: &str) -> Result<()> {
    let new_map: FilterFlowDescMap = serde_yaml::from_str(rules_str)?;
    let _lock = REPLACE_RULES_MUTEX.lock().unwrap();
    SHARE_FILTER_FLOW_DESC.clear();
    for it in new_map.iter() {
        SHARE_FILTER_FLOW_DESC.insert(it.key().clone(), it.value().clone());
    }
    Ok(())
}

// 搜索子域名规则
fn search_rules(
    source: &DashMap<String, Option<FilterFlowDesc>>,
    key_stack: &mut Vec<&str>,
) -> Option<FilterFlowDesc> {
    if let Some(key) = key_stack.pop()
        && let Some(item) = source.get(key)
    {
        if let Some(desc) = item.value() {
            if let Some(rules) = &desc.rules
                && let Some(result) = search_rules(rules, key_stack)
            {
                // 查找子域名规则
                return Some(result);
            }
            return Some(desc.clone());
        }
        return Some(FilterFlowDesc::default());
    }
    None
}
pub fn start_search_rules(host: &str) -> Option<FilterFlowDesc> {
    let mut spl = find_match_suffix(host, '.');
    search_rules(&SHARE_FILTER_FLOW_DESC, &mut spl)
}

// 搜索路径规则
fn search_paths(
    source: &DashMap<String, Option<FilterFlowDesc>>,
    key_stack: &mut Vec<&str>,
) -> Option<FilterFlowDesc> {
    if let Some(key) = key_stack.pop()
        && let Some(item) = source.get(key)
        && let Some(desc) = item.value()
    {
        if let Some(paths) = &desc.paths
            && let Some(result) = search_paths(paths, key_stack)
        {
            // 查找子域名规则
            return Some(result);
        }
        return Some(desc.clone());
    }
    None
}
pub fn start_search_paths(path: &str, desc: &FilterFlowDesc) -> Option<FilterFlowDesc> {
    let mut spl = find_match_suffix(path, '/');
    if let Some(paths) = &desc.paths {
        return search_paths(paths, &mut spl);
    }
    None
}
//
// pub async fn filter_local_dns_by_rules(host: &str) -> Result<u32> {
//     let (sub_domain, domain) = find_match_suffix(host);
//     if let Some(rules_group) = SHARE_FILTER_FLOW_DESC.get(domain) {
//         if let Some(rules) = &rules_group.rules {
//             if let Some(result) = match_sub_domain(rules, sub_domain) {
//                 if let Some(ip_v4) = result.redirect_v4 {
//                     return Ok(ip_v4);
//                 }
//                 if let Some(replace_host) = result.host {
//                     return query_local_dns(replace_host.as_str()).await;
//                 }
//             }
//         }
//     }
//     query_local_dns(host).await
// }

fn find_match_suffix(host: &str, c: char) -> Vec<&str> {
    let mut r = Vec::new();
    let mut p = host;
    loop {
        if let Some(index) = p.find(c) {
            // 使用 get 获取子串
            r.push(&p[..index]);
            p = &p[(index + 1)..];
        } else {
            break;
        }
    }
    r
}

pub async fn load_test_rule() -> Result<()> {
    let rules = fs::read_to_string("test_rule.yaml").await?;
    refresh_filter_flow(rules.as_str())
}
