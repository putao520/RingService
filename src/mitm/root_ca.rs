use anyhow::Result;

use crate::windows::cert_system::CertSystem;

pub struct RootCa {
    cs: CertSystem,
}

impl RootCa {
    pub async fn new() -> Result<Self> {
        let cert_system = CertSystem::new().await?;
        Ok(RootCa { cs: cert_system })
    }

    pub fn add(&mut self) -> bool {
        return self.cs.store_ca();
    }

    pub fn remove(&mut self) -> bool {
        return self.cs.remove_ca();
    }

    pub fn print(&mut self) {
        self.cs.print_ca();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_root_ca() {
        let mut root_ca = RootCa::new().await.unwrap();

        // 导入系统库
        root_ca.add();

        // 删除系统库
        // root_ca.remove().unwrap();

        assert!(true)
    }
}
