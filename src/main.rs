mod cloud;
mod crypto;
mod dpi;
mod proxy;
mod sdwan;
mod ztna;

use cloud::CloudSync;
use crypto::CryptoEngine;
use dpi::DpiEngine;
use proxy::ContentInspector;
use sdwan::SdWanRouter;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use ztna::ZtnaValidator;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("=== SASE Edge Node Data Plane Starting ===");

    // 1. Модуль шифрования
    let crypto = CryptoEngine::new();
    let sample_data = b"Internal SASE Control Plane Token";
    let nonce = [7u8; 12];
    match crypto.encrypt(sample_data, nonce) {
        Ok(ciphertext) => {
            tracing::info!("[CRYPTO] AES-256-GCM test encryption OK ({} bytes)", ciphertext.len());
            let decrypted = crypto.decrypt(ciphertext, nonce).unwrap();
            assert_eq!(sample_data.to_vec(), decrypted);
        }
        Err(_) => tracing::error!("[CRYPTO] Encryption failed"),
    }

    // 2. Модуль L7 инспекции и декомпрессии
    let raw_payload = b"Example payload containing RESTRICTED_INTERNAL_KEY";
    let _ = ContentInspector::inspect_and_decompress(None, raw_payload);

    // 3. Инициализация SD-WAN маршрутизатора
    let sdwan = SdWanRouter::new();
    sdwan.register_link("mpls", 10);
    sdwan.register_link("broadband_isp", 50);

    let sdwan_probe_task = sdwan.clone();
    tokio::spawn(async move {
        sdwan_probe_task.run_probes().await;
    });

    // 4. Инициализация ZTNA
    let _ztna = ZtnaValidator::new("SASE_SUPER_SECRET_HMAC_KEY");

    // 5. Инициализация DPI движка
    let dpi = Arc::new(DpiEngine::new("eth0"));
    let dpi_worker = Arc::clone(&dpi);

    std::thread::spawn(move || {
        dpi_worker.start_capture();
    });

    // 6. Фоновый цикл телеметрии и мониторинга каналов
    let cloud_sync = CloudSync::new("http://127.0.0.1:8080");
    let dpi_stat = Arc::clone(&dpi);
    let sdwan_monitor = sdwan.clone();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            if let Some(path) = sdwan_monitor.get_optimal_path() {
                let dropped = dpi_stat.blocked_packets_count.load(Ordering::Relaxed);
                tracing::info!(
                    "[SD-WAN ROUTE] Active path: [{}] | Total Firewall Drops: {}",
                    path,
                    dropped
                );

                // Отправка в облако (продолжает работу при отсутствии локального mock-сервера)
                let _ = cloud_sync.push_telemetry("edge-node-01", &path, dropped).await;
            }
        }
    });

    // Ожидание завершения по Ctrl+C
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for SIGINT");
    tracing::info!("Shutdown signal received. Terminating SASE Node.");
}
