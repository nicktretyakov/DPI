use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct WanLinkMetrics {
    pub latency_ms: u64,
    pub packet_loss_percent: f32,
    pub active: bool,
}

#[derive(Clone)]
pub struct SdWanRouter {
    links: Arc<RwLock<HashMap<String, WanLinkMetrics>>>,
}

impl SdWanRouter {
    pub fn new() -> Self {
        Self {
            links: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_link(&self, name: &str, initial_latency: u64) {
        let mut links = self.links.write().unwrap();
        links.insert(
            name.to_string(),
            WanLinkMetrics {
                latency_ms: initial_latency,
                packet_loss_percent: 0.0,
                active: true,
            },
        );
    }

    pub fn get_optimal_path(&self) -> Option<String> {
        let links = self.links.read().unwrap();
        links
            .iter()
            .filter(|(_, metrics)| metrics.active && metrics.packet_loss_percent < 5.0)
            .min_by_key(|(_, metrics)| metrics.latency_ms)
            .map(|(name, _)| name.clone())
    }

    pub async fn run_probes(self) {
        loop {
            {
                let mut links = self.links.write().unwrap();
                for (name, metrics) in links.iter_mut() {
                    // Эмуляция зондирования каналов (ICMP/UDP probe jitter)
                    if name == "mpls" {
                        metrics.latency_ms = 12;
                        metrics.packet_loss_percent = 0.0;
                    } else if name == "broadband_isp" {
                        metrics.latency_ms = 45;
                        metrics.packet_loss_percent = 1.2;
                    }
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }
}
