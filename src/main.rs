#![feature(let_chains)]
#![feature(fn_traits)]

use mimalloc::MiMalloc;
use tokio::runtime::Builder;

use crate::conf::transport::Transport;
use crate::mitm::filter_flow::{FilterFlow, RULES_THEME_NAME};
use crate::mitm::gsc_dns_resolver::{REGIONS, REGION_THEME_NAME};
use crate::mitm::mitm::mitm_start;
use crate::mitm::root_ca::RootCa;

mod conf;
mod extranal;
mod mitm;
mod utils;
mod windows;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    // env::set_var("RUST_LOG", "debug");
    // env_logger::init();
    println!("Hello, world!");
    // 创建Tokio运行时
    let runtime = Builder::new_multi_thread()
        // .worker_threads(4) // 设置工作线程数量
        .max_blocking_threads(1000) // 设置最大阻塞线程数量
        .enable_all()
        .build()
        .unwrap();

    // 使用创建的运行时运行异步代码
    runtime.block_on(async {
        // 加载规则
        let mut conf_watcher = Transport::new().await.unwrap();
        conf_watcher
            .subscribe(RULES_THEME_NAME, Box::new(FilterFlow {}))
            .await
            .unwrap();
        conf_watcher
            .subscribe(REGION_THEME_NAME, Box::new(REGIONS {}))
            .await
            .unwrap();

        // 创建一个 tokio 的mpsc通道
        let (_, rx) = tokio::sync::mpsc::channel(1);

        let mut root_ca = RootCa::new().await.unwrap();

        // 导入系统库
        root_ca.add();

        // root_ca.print();

        mitm_start(rx).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(1000 * 86400)).await;

        root_ca.remove();
    });
    println!("finish!");
}
