use anyhow::Result;
use std::ffi::{CStr, CString};

use crate::extranal::ring_external::StartSystemProxy;
use crate::mitm::dns::RingResolver;
use crate::mitm::filter_flow::{
    print_flow_desc, start_search_paths, start_search_rules, FilterFlowDesc,
};
use crate::windows::cert_system::CertSystem;
use hudsucker::certificate_authority::OpensslAuthority;
use hudsucker::hyper_util::client::legacy::connect::HttpConnector;
use hudsucker::hyper_util::client::legacy::Client;
use hudsucker::hyper_util::rt::TokioExecutor;
use hudsucker::rules::RuleHandler;
use hudsucker::rustls::crypto::CryptoProvider;
use hudsucker::rustls::ClientConfig;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response},
    rcgen::{CertificateParams, KeyPair},
    tokio_tungstenite::tungstenite::Message,
    *,
};
use hyper::http::uri::{Authority, Scheme};
use hyper::{http, StatusCode, Uri};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::*;
/*
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}
*/

#[derive(Clone)]
struct NSFWHandler;
impl HttpHandler<FilterFlowDesc> for NSFWHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
        rules: Option<FilterFlowDesc>,
    ) -> RequestOrResponse {
        // 请求过滤
        if let Some(r) = rules
            && let Some(nsfw) = r.nsfw
        {
            match nsfw {
                4 => {
                    let res = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::empty())
                        .unwrap();
                    return res.into();
                }
                _ => {}
            }
        }
        req.into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        mut res: Response<Body>,
        _rules: Option<FilterFlowDesc>,
    ) -> Response<Body> {
        // 修改响应头, 添加跨域头
        let headers = res.headers_mut();
        headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
        headers.insert(
            "Access-Control-Allow-Methods",
            "GET, POST, OPTIONS".parse().unwrap(),
        );

        // println!("{:?}", res);

        if let Some(rule) = _rules {
            if let Some(nsfw) = rule.nsfw {
                if nsfw == 9 {
                    let r_headers = res.headers();
                    for (key, value) in r_headers {
                        println!("{}: {:?}", key, value);
                    }
                    println!("NSFW: {:?}", res);
                }
            }
        }
        res
    }
}

impl WebSocketHandler for NSFWHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        // println!("{:?}", msg);
        Some(msg)
    }
}

#[derive(Clone)]
struct SNIHandler;

impl RuleHandler<FilterFlowDesc> for SNIHandler {
    async fn get_rules(&mut self, uri: &Uri) -> Option<FilterFlowDesc> {
        match uri.host() {
            None => None,
            Some(host) => {
                // 查找规则
                let desc = start_search_rules(host).await;
                match desc {
                    Some(d) => match start_search_paths(uri.path(), &d) {
                        Some(p) => Some(p),
                        None => Some(d),
                    },
                    None => None,
                }
            }
        }
    }

    async fn sni_filter(&mut self, uri: &mut Uri, rule: Option<FilterFlowDesc>) -> bool {
        match &rule {
            Some(r) => {
                if let Some(p) = &r.proxy {
                    // 更改请求host
                    let new_url = Uri::from_parts({
                        let mut parts = uri.clone().into_parts();
                        parts.authority = Some(Authority::from_str(p.as_str()).unwrap());
                        parts
                    })
                    .unwrap();
                    *uri = new_url;
                }

                true
            }
            None => false,
        }
    }
}

pub async fn build_free_tcp_server() -> Result<(TcpListener, u16)> {
    for port in 3000..60000 {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr).await;
        match listener {
            Ok(l) => {
                info!("Listening on: {}", addr);
                return Ok((l, port));
            }
            Err(_) => {
                continue;
            }
        }
    }
    Err(anyhow::anyhow!("Failed to bind to any port"))
}

pub fn build_no_sni_client() -> Client<HttpsConnector<HttpConnector<RingResolver>>, Body> {
    // let mut config = ClientConfig::builder()
    //     .with_webpki_roots()
    //     .with_no_client_auth();
    //
    // config.enable_sni = false;

    let mut config = ClientConfig::builder()
        .with_native_roots()
        .unwrap()
        .with_no_client_auth();
    config.enable_early_data = true;
    // config.enable_sni = false;

    let mut http = HttpConnector::new_with_resolver(RingResolver::new());
    http.enforce_http(false);

    let mut https = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http);

    https.enforce_https();

    let client = Client::builder(TokioExecutor::new())
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(https);

    client
}

pub async fn mitm_start(mut shutdown_ch: tokio::sync::mpsc::Receiver<()>) -> Result<()> {
    tracing_subscriber::fmt::init();

    let ca_system = CertSystem::new().await?;

    let (cert_root, private_key) = ca_system.get_cert_pem().await?;

    // let private_key = KeyPair::from_pem(String::from_utf8(private_key)?.as_str())
    //     .expect("Failed to parse private key");
    // let ca_cert = CertificateParams::from_ca_cert_pem(String::from_utf8(cert_root)?.as_str())
    //     .expect("Failed to parse CA certificate")
    //     .self_signed(&key_pair)
    //     .expect("Failed to sign CA certificate");
    // let ca = RcgenAuthority::new(private_key, ca_cert, 1_000);

    let private_key =
        PKey::private_key_from_pem(private_key.as_slice()).expect("Failed to parse private key");
    let ca_cert = X509::from_pem(cert_root.as_slice()).expect("Failed to parse CA certificate");

    let ca = OpensslAuthority::new(private_key, ca_cert, MessageDigest::sha256(), 1_000);

    let shutdown_signal = async move {
        shutdown_ch.recv().await;
        info!("Shutting down...");
    };

    let (tcp_listen, port) = build_free_tcp_server().await?;

    let proxy = Proxy::builder()
        .with_listener(tcp_listen)
        .with_rustls_client()
        .with_ca(ca)
        .with_rule_flow(SNIHandler)
        .with_no_sni_client(build_no_sni_client())
        .with_http_handler(NSFWHandler)
        .with_websocket_handler(NSFWHandler)
        .with_graceful_shutdown(shutdown_signal)
        .build();

    let proxy_peer = CString::new(format!("127.0.0.1:{}", port))?;
    unsafe { StartSystemProxy(proxy_peer.as_ptr() as *const u8) }

    if let Err(e) = proxy.start().await {
        error!("{}", e);
    }

    Ok(())
}
