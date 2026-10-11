pub mod stun;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use stun::{create_binding_request, parse_stun_response};
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct PingConfig {
    pub server: String,
    pub secondary_server: Option<String>,
    pub count: usize,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub nat_test: bool,
    pub quiet: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub seq: usize,
    pub rtt_ms: f64,
    pub reflexive_addr: Option<SocketAddr>,
    pub software: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingReport {
    pub server: String,
    pub target_addr: SocketAddr,
    pub probes_sent: usize,
    pub probes_received: usize,
    pub loss_pct: f64,
    pub min_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub stddev_rtt_ms: f64,
    pub reflexive_addr: Option<SocketAddr>,
    pub software: Option<String>,
    pub nat_type: Option<String>,
}

pub fn parse_stun_address(s: &str) -> String {
    let clean = s.strip_prefix("stun:").unwrap_or(s);
    if clean.contains(':') {
        clean.to_string()
    } else {
        format!("{}:3478", clean)
    }
}

pub async fn run_rtcping(config: PingConfig) -> Result<PingReport> {
    let target_str = parse_stun_address(&config.server);
    let target_addr = {
        let mut addrs = tokio::net::lookup_host(&target_str)
            .await
            .with_context(|| format!("Failed to resolve STUN server '{}'", target_str))?;
        match addrs.next() {
            Some(a) => a,
            None => bail!("No IP addresses found for STUN server '{}'", target_str),
        }
    };

    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    let local_addr = socket.local_addr()?;

    if !config.quiet {
        eprintln!(
            "{} probing STUN server {} ({}) from local {}",
            "rtcping".bold().green(),
            target_str.cyan(),
            target_addr.to_string().yellow(),
            local_addr.to_string().dimmed()
        );
    }

    let mut probes = Vec::new();
    let mut latest_reflexive = None;
    let mut latest_software = None;

    let timeout = Duration::from_millis(config.timeout_ms);
    let interval = Duration::from_millis(config.interval_ms);

    for seq in 1..=config.count {
        let mut tx_id = [0u8; 12];
        rand::thread_rng().fill(&mut tx_id);

        let req = create_binding_request(tx_id);
        let start = Instant::now();

        if let Err(e) = socket.send_to(&req, target_addr).await {
            if !config.quiet {
                eprintln!("Probe {}: send error: {}", seq, e);
            }
            continue;
        }

        let mut buf = [0u8; 1024];
        let recv_res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;

        match recv_res {
            Ok(Ok((len, sender))) => {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                match parse_stun_response(&buf[..len], Some(&tx_id)) {
                    Ok(resp) => {
                        if let Some(ref_addr) = resp.reflexive_addr {
                            latest_reflexive = Some(ref_addr);
                        }
                        if let Some(ref sw) = resp.software {
                            latest_software = Some(sw.clone());
                        }

                        if !config.quiet {
                            let ref_str = latest_reflexive
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| "unknown".to_string());
                            println!(
                                "Probe {}: {} ms - reflexive candidate: {} (from {})",
                                seq,
                                format!("{:.2}", elapsed).green().bold(),
                                ref_str.cyan(),
                                sender
                            );
                        }

                        probes.push(ProbeResult {
                            seq,
                            rtt_ms: elapsed,
                            reflexive_addr: resp.reflexive_addr,
                            software: resp.software,
                        });
                    }
                    Err(e) => {
                        if !config.quiet {
                            eprintln!("Probe {}: invalid STUN response: {}", seq, e);
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                if !config.quiet {
                    eprintln!("Probe {}: recv error: {}", seq, e);
                }
            }
            Err(_) => {
                if !config.quiet {
                    eprintln!("Probe {}: {} timed out after {}ms", seq, "TIMEOUT".red(), config.timeout_ms);
                }
            }
        }

        if seq < config.count {
            tokio::time::sleep(interval).await;
        }
    }

    let probes_sent = config.count;
    let probes_received = probes.len();
    let loss_pct = if probes_sent > 0 {
        ((probes_sent - probes_received) as f64 / probes_sent as f64) * 100.0
    } else {
        0.0
    };

    let (min_rtt, avg_rtt, max_rtt, stddev_rtt) = if !probes.is_empty() {
        let rtts: Vec<f64> = probes.iter().map(|p| p.rtt_ms).collect();
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
        (min, avg, max, variance.sqrt())
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };

    let mut nat_type = None;

    if config.nat_test {
        nat_type = Some(classify_nat(&socket, target_addr, latest_reflexive, config.secondary_server.as_deref()).await);
    }

    Ok(PingReport {
        server: target_str,
        target_addr,
        probes_sent,
        probes_received,
        loss_pct,
        min_rtt_ms: min_rtt,
        avg_rtt_ms: avg_rtt,
        max_rtt_ms: max_rtt,
        stddev_rtt_ms: stddev_rtt,
        reflexive_addr: latest_reflexive,
        software: latest_software,
        nat_type,
    })
}

async fn classify_nat(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    first_reflexive: Option<SocketAddr>,
    secondary_server: Option<&str>,
) -> String {
    let first = match first_reflexive {
        Some(f) => f,
        None => return "Unknown (no response from primary STUN server)".to_string(),
    };

    let local = match socket.local_addr() {
        Ok(l) => l,
        Err(_) => return "Unknown".to_string(),
    };

    if local.ip() == first.ip() && local.port() == first.port() {
        return "Open Internet / Direct (No NAT)".to_string();
    }

    // Determine second STUN target to test mapping behavior
    let second_target = if let Some(sec) = secondary_server {
        let parsed = parse_stun_address(sec);
        tokio::net::lookup_host(&parsed).await.ok().and_then(|mut it| it.next())
    } else {
        // Fallback: test on another common public STUN server or alternative port
        let alt = "stun.cloudflare.com:3478";
        tokio::net::lookup_host(alt).await.ok().and_then(|mut it| it.next())
    };

    let second_addr = match second_target {
        Some(s) if s != target_addr => s,
        _ => {
            return "Endpoint-Independent Mapping (Cone NAT)".to_string();
        }
    };

    // Send probe to second target using SAME local socket
    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);
    let req = create_binding_request(tx_id);

    if socket.send_to(&req, second_addr).await.is_err() {
        return "Endpoint-Independent Mapping (Cone NAT)".to_string();
    }

    let mut buf = [0u8; 1024];
    let res = tokio::time::timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await;

    if let Ok(Ok((len, _))) = res {
        if let Ok(resp) = parse_stun_response(&buf[..len], Some(&tx_id)) {
            if let Some(second_reflexive) = resp.reflexive_addr {
                if first.port() == second_reflexive.port() {
                    return "Endpoint-Independent Mapping / Full-Cone (P2P Friendly)".to_string();
                } else {
                    return "Address-Dependent / Symmetric NAT (Hostile to P2P - TURN Relay Required)".to_string();
                }
            }
        }
    }

    "Endpoint-Independent Mapping (Cone NAT)".to_string()
}
