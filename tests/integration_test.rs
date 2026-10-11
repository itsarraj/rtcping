use rtcping::stun::{
    ATTR_SOFTWARE, ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST, BINDING_RESPONSE, MAGIC_COOKIE,
};
use rtcping::{run_rtcping, PingConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

async fn spawn_mock_stun_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);

    let s = Arc::clone(&socket);
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((len, client_addr)) = s.recv_from(&mut buf).await {
            if len >= 20 {
                let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                if msg_type == BINDING_REQUEST && cookie == MAGIC_COOKIE {
                    let mut tx_id = [0u8; 12];
                    tx_id.copy_from_slice(&buf[8..20]);

                    let mut resp = Vec::new();
                    resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());

                    // Attributes: XOR-MAPPED-ADDRESS (12 bytes) + SOFTWARE (16 bytes)
                    let software = b"MockCoturn/1.0";
                    let sw_padded_len = 16; // 14 bytes + 2 padding

                    let total_attr_len = 12 + (4 + sw_padded_len);
                    resp.extend_from_slice(&(total_attr_len as u16).to_be_bytes());
                    resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
                    resp.extend_from_slice(&tx_id);

                    // 1. XOR-MAPPED-ADDRESS
                    resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
                    resp.extend_from_slice(&8u16.to_be_bytes()); // attr length
                    resp.push(0x00); // reserved
                    resp.push(0x01); // IPv4 family

                    let xor_port = client_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
                    resp.extend_from_slice(&xor_port.to_be_bytes());

                    let ip_v4 = match client_addr.ip() {
                        std::net::IpAddr::V4(ip) => u32::from(ip),
                        _ => 0x7f000001,
                    };
                    let xor_ip = ip_v4 ^ MAGIC_COOKIE;
                    resp.extend_from_slice(&xor_ip.to_be_bytes());

                    // 2. SOFTWARE attribute
                    resp.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
                    resp.extend_from_slice(&(software.len() as u16).to_be_bytes());
                    resp.extend_from_slice(software);
                    // 2 bytes padding to 4-byte boundary
                    resp.push(0x00);
                    resp.push(0x00);

                    let _ = s.send_to(&resp, client_addr).await;
                }
            }
        }
    });

    addr
}

#[tokio::test]
async fn test_rtcping_mock_stun_server() {
    let server_addr = spawn_mock_stun_server().await;

    let config = PingConfig {
        server: server_addr.to_string(),
        secondary_server: None,
        count: 3,
        interval_ms: 50,
        timeout_ms: 1000,
        nat_test: false,
        quiet: true,
    };

    let report = run_rtcping(config).await.expect("rtcping should succeed");

    assert_eq!(report.probes_sent, 3);
    assert_eq!(report.probes_received, 3);
    assert_eq!(report.loss_pct, 0.0);
    assert!(report.reflexive_addr.is_some());
    assert_eq!(report.software, Some("MockCoturn/1.0".to_string()));
    assert!(report.avg_rtt_ms >= 0.0);
}

#[tokio::test]
async fn test_rtcping_nat_classification() {
    let server_addr = spawn_mock_stun_server().await;

    let config = PingConfig {
        server: server_addr.to_string(),
        secondary_server: Some(server_addr.to_string()),
        count: 2,
        interval_ms: 50,
        timeout_ms: 1000,
        nat_test: true,
        quiet: true,
    };

    let report = run_rtcping(config).await.expect("rtcping should succeed");

    assert_eq!(report.probes_received, 2);
    assert!(report.nat_type.is_some());
}
