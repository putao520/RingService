use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use hudsucker::tokio_tungstenite::tungstenite::Message;
use hudsucker::tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cmd {
    name: String,
    data: String,
}

#[cfg(debug_assertions)]
static TRANSPORT_URL: &str = "ws://127.0.0.1:3000";
#[cfg(not(debug_assertions))]
static TRANSPORT_URL: Uri = Uri::from_static("ws://127.0.0.1:3000");

pub type TransportResult = Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>>;
pub trait TransportCallback: Send + Sync {
    // async fn invoke(&self, data: &str) -> Result<(), anyhow::Error>;
    fn invoke(&self, data: String) -> TransportResult;
}

pub struct Transport {
    client: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    handle: JoinHandle<()>,
    subscribe_callback: Arc<DashMap<String, Box<dyn TransportCallback>>>,
}

impl Transport {
    pub async fn new() -> Result<Self> {
        let subscribe_callback = Arc::new(DashMap::<String, Box<dyn TransportCallback>>::new());
        let (mut ws_stream, _) = connect_async(Url::parse(TRANSPORT_URL).unwrap())
            .await
            .unwrap();

        let (mut reader, mut writer) = ws_stream.split();
        let subscribe_callback_clone = Arc::clone(&subscribe_callback);
        let handle = tokio::spawn(async move {
            let subscribe_callback_clone = Arc::clone(&subscribe_callback);
            while let Some(Ok(msg)) = writer.next().await {
                if let Ok(data) = msg.to_text() {
                    if let Ok(cmd) = serde_json::from_str::<Cmd>(data) {
                        if subscribe_callback_clone.contains_key(cmd.name.as_str()) {
                            if let Some(callback) = subscribe_callback_clone.get(cmd.name.as_str())
                            {
                                let cb = callback.value();
                                let pinned_cb = Box::pin(cb.invoke(cmd.data));
                                if let Ok(_) = pinned_cb.await {}
                            }
                        }
                    }
                }
            }
        });
        Ok(Self {
            client: reader,
            handle,
            subscribe_callback: subscribe_callback_clone,
        })
    }

    pub async fn subscribe(
        &mut self,
        theme_name: &str,
        callback: Box<dyn TransportCallback>,
    ) -> Result<bool> {
        if self.subscribe_callback.contains_key(theme_name) {
            return Ok(false);
        }
        let cmd = Cmd {
            name: "add".to_string(),
            data: theme_name.to_string(),
        };
        let cmd = serde_json::to_string(&cmd).unwrap();
        if let Ok(_) = self.client.send(Message::text(cmd)).await {
            self.subscribe_callback
                .insert(theme_name.to_string(), callback);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn unsubscribe(&mut self, theme_name: &str) -> Result<bool> {
        if !self.subscribe_callback.contains_key(theme_name) {
            return Ok(false);
        }
        let cmd = Cmd {
            name: "del".to_string(),
            data: theme_name.to_string(),
        };
        let cmd = serde_json::to_string(&cmd).unwrap();
        if let Ok(_) = self.client.send(Message::text(cmd)).await {
            self.subscribe_callback.remove(theme_name);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
