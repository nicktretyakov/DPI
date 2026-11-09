use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct TelemetryPayload {
    pub edge_id: String,
    pub optimal_wan_link: String,
    pub total_blocked_packets: u64,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SecurityPolicyRule {
    pub blocked_countries: Vec<String>,
    pub block_http: bool,
    pub block_plain_dns: bool,
}

pub struct CloudSync {
    client: Client,
    endpoint: String,
}

impl CloudSync {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
            endpoint: endpoint.to_string(),
        }
    }

    pub async fn fetch_latest_policies(&self) -> Result<SecurityPolicyRule, reqwest::Error> {
        let resp = self
            .client
            .get(format!("{}/v1/policies", self.endpoint))
            .header("Authorization", "Bearer SASE_DYNAMIC_CONTROL_TOKEN")
            .send()
            .await?
            .json::<SecurityPolicyRule>()
            .await?;
        Ok(resp)
    }

    pub async fn push_telemetry(
        &self,
        edge_id: &str,
        link: &str,
        dropped: u64,
    ) -> Result<(), reqwest::Error> {
        let payload = TelemetryPayload {
            edge_id: edge_id.to_string(),
            optimal_wan_link: link.to_string(),
            total_blocked_packets: dropped,
        };

        self.client
            .post(format!("{}/v1/telemetry", self.endpoint))
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }
}
