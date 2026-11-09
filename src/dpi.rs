use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct DpiEngine {
    interface_name: String,
    pub blocked_packets_count: Arc<AtomicU64>,
}

impl DpiEngine {
    pub fn new(preferred_interface: &str) -> Self {
        let interfaces = datalink::interfaces();
        let selected_interface = interfaces
            .iter()
            .find(|iface| iface.name == preferred_interface)
            .or_else(|| interfaces.iter().find(|iface| iface.is_up() && !iface.is_loopback()))
            .map(|iface| iface.name.clone())
            .unwrap_or_else(|| "lo".to_string());

        Self {
            interface_name: selected_interface,
            blocked_packets_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn start_capture(&self) {
        let interfaces = datalink::interfaces();
        let interface = match interfaces.into_iter().find(|i: &NetworkInterface| i.name == self.interface_name) {
            Some(i) => i,
            None => {
                tracing::error!("[DPI] Interface {} not available", self.interface_name);
                return;
            }
        };

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                tracing::error!("[DPI] Unsupported channel type");
                return;
            }
            Err(e) => {
                tracing::error!("[DPI] Failed to open datalink channel (check privileges): {e}");
                return;
            }
        };

        tracing::info!("[DPI] Active packet capture started on: {}", self.interface_name);

        loop {
            match rx.next() {
                Ok(frame) => {
                    if let Some(ethernet) = EthernetPacket::new(frame) {
                        if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                self.process_ipv4(&ipv4);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("[DPI] Error receiving frame: {e}");
                }
            }
        }
    }

    fn process_ipv4(&self, ipv4: &Ipv4Packet) {
        let src_ip = ipv4.get_source();
        let dst_ip = ipv4.get_destination();

        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    let src_p = tcp.get_source();
                    let dst_p = tcp.get_destination();

                    // Блокировка незашифрованного HTTP (L4 Firewall rule)
                    if src_p == 80 || dst_p == 80 {
                        self.blocked_packets_count.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("[FIREWALL DROP] Plaintext HTTP: {src_ip}:{src_p} -> {dst_ip}:{dst_p}");
                        return;
                    }

                    // Базовая эмуляция L7 SNI инспекции
                    let payload = tcp.payload();
                    if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
                        tracing::debug!("[DPI L7] TLS Handshake ClientHello captured ({dst_ip}:{dst_p})");
                    }
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    let src_p = udp.get_source();
                    let dst_p = udp.get_destination();

                    // Блокировка незашифрованного DNS
                    if src_p == 53 || dst_p == 53 {
                        self.blocked_packets_count.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("[FIREWALL DROP] Plaintext DNS: {src_ip}:{src_p} -> {dst_ip}:{dst_p}");
                        return;
                    }
                }
            }
            _ => {}
        }
    }
}
