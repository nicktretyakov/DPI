use flate2::read::GzDecoder;
use std::io::Read;

pub struct ContentInspector;

impl ContentInspector {
    pub fn inspect_and_decompress(encoding: Option<&str>, payload: &[u8]) -> Result<String, std::io::Error> {
        let mut decompressed = Vec::new();
        match encoding {
            Some("gzip") => {
                let mut decoder = GzDecoder::new(payload);
                decoder.read_to_end(&mut decompressed)?;
            }
            _ => {
                decompressed = payload.to_vec();
            }
        }

        let body_str = String::from_utf8_lossy(&decompressed).to_string();

        if body_str.contains("RESTRICTED_INTERNAL_KEY") {
            tracing::warn!("[DLP ALERT] Data leakage pattern detected in packet payload!");
        }

        Ok(body_str)
    }
}
