use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_ERROR_CODE: u16 = 0x0009;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResponse {
    pub message_type: u16,
    pub transaction_id: [u8; 12],
    pub reflexive_addr: Option<SocketAddr>,
    pub software: Option<String>,
    pub error: Option<(u16, String)>,
}

/// Create a 20-byte STUN Binding Request packet
pub fn create_binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes()); // Message Type (0x0001)
    buf.extend_from_slice(&0u16.to_be_bytes());            // Message Length (0)
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());   // Magic Cookie (0x2112A442)
    buf.extend_from_slice(&transaction_id);               // 12 bytes Transaction ID
    buf
}

/// Parse a raw STUN packet from UDP
pub fn parse_stun_response(buf: &[u8], expected_tx_id: Option<&[u8; 12]>) -> Result<StunResponse> {
    if buf.len() < 20 {
        bail!("STUN packet too short: {} bytes (minimum 20)", buf.len());
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    if cookie != MAGIC_COOKIE {
        bail!("Invalid STUN magic cookie: 0x{:08x}", cookie);
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&buf[8..20]);

    if let Some(expected) = expected_tx_id {
        if &transaction_id != expected {
            bail!("STUN transaction ID mismatch");
        }
    }

    if buf.len() < 20 + msg_len {
        bail!("STUN payload truncated: expected {} bytes, got {}", 20 + msg_len, buf.len());
    }

    let mut reflexive_addr = None;
    let mut software = None;
    let mut error = None;

    let mut offset = 20;
    let end = 20 + msg_len;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > end {
            break;
        }

        let attr_val = &buf[offset..offset + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Ok(addr) = parse_xor_mapped_address(attr_val, &transaction_id) {
                    reflexive_addr = Some(addr);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if reflexive_addr.is_none() {
                    if let Ok(addr) = parse_mapped_address(attr_val) {
                        reflexive_addr = Some(addr);
                    }
                }
            }
            ATTR_SOFTWARE => {
                if let Ok(s) = std::str::from_utf8(attr_val) {
                    software = Some(s.to_string());
                }
            }
            ATTR_ERROR_CODE => {
                if attr_val.len() >= 4 {
                    let class = attr_val[2] as u16;
                    let number = attr_val[3] as u16;
                    let code = class * 100 + number;
                    let reason = String::from_utf8_lossy(&attr_val[4..]).to_string();
                    error = Some((code, reason));
                }
            }
            _ => {}
        }

        // Align to 4-byte boundary
        let padding = (4 - (attr_len % 4)) % 4;
        offset += attr_len + padding;
    }

    Ok(StunResponse {
        message_type: msg_type,
        transaction_id,
        reflexive_addr,
        software,
        error,
    })
}

fn parse_xor_mapped_address(val: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    if val.len() < 8 {
        bail!("XOR-MAPPED-ADDRESS attribute too short");
    }

    let family = val[1];
    let raw_port = u16::from_be_bytes([val[2], val[3]]);
    let port = raw_port ^ ((MAGIC_COOKIE >> 16) as u16);

    match family {
        0x01 => {
            // IPv4 (4 bytes)
            if val.len() < 8 {
                bail!("XOR-MAPPED-ADDRESS IPv4 too short");
            }
            let raw_ip = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
            let ip = Ipv4Addr::from(raw_ip ^ MAGIC_COOKIE);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6 (16 bytes)
            if val.len() < 20 {
                bail!("XOR-MAPPED-ADDRESS IPv6 too short");
            }
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor_key[4..].copy_from_slice(transaction_id);

            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = val[4 + i] ^ xor_key[i];
            }
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => bail!("Unsupported address family: 0x{:02x}", family),
    }
}

fn parse_mapped_address(val: &[u8]) -> Result<SocketAddr> {
    if val.len() < 8 {
        bail!("MAPPED-ADDRESS attribute too short");
    }

    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);

    match family {
        0x01 => {
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if val.len() < 20 {
                bail!("MAPPED-ADDRESS IPv6 too short");
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&val[4..20]);
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => bail!("Unsupported address family: 0x{:02x}", family),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_request_creation() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = create_binding_request(tx_id);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..20], &tx_id);
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let target_ip = Ipv4Addr::new(192, 0, 2, 1);
        let target_port = 54320u16;

        // XOR port with high 16 bits of MAGIC_COOKIE (0x2112)
        let xor_port = target_port ^ 0x2112;
        // XOR IP with MAGIC_COOKIE
        let xor_ip = u32::from(target_ip) ^ MAGIC_COOKIE;

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes()); // attr length = 12
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&tx_id);

        // Attribute XOR-MAPPED-ADDRESS
        pkt.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes()); // attr length
        pkt.push(0x00); // reserved
        pkt.push(0x01); // IPv4
        pkt.extend_from_slice(&xor_port.to_be_bytes());
        pkt.extend_from_slice(&xor_ip.to_be_bytes());

        let res = parse_stun_response(&pkt, Some(&tx_id)).unwrap();
        assert_eq!(res.message_type, BINDING_RESPONSE);
        assert_eq!(
            res.reflexive_addr,
            Some(SocketAddr::new(IpAddr::V4(target_ip), target_port))
        );
    }
}
