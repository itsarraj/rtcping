use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use rtcping::{run_rtcping, PingConfig};

#[derive(Parser, Debug)]
#[command(
    name = "rtcping",
    author = "Animesh Raj <animesh080808@gmail.com>",
    version,
    about = "WebRTC STUN connectivity tester, NAT traversal classifier, and reflexive candidate latency benchmark",
    after_help = "EXAMPLES:\n  \
      rtcping stun.l.google.com:19302\n  \
      rtcping stun:stun.cloudflare.com:3478 --count 10 --interval-ms 200\n  \
      rtcping turn.mycompany.com:3478 --nat-test\n  \
      rtcping 127.0.0.1:3478 --json"
)]
struct Cli {
    /// STUN server address or URI (e.g. stun:stun.l.google.com:19302)
    #[arg(default_value = "stun.l.google.com:19302")]
    server: String,

    /// Secondary STUN server for NAT classification test
    #[arg(long)]
    secondary: Option<String>,

    /// Number of STUN binding request probes to send
    #[arg(short = 'c', long, default_value_t = 5)]
    count: usize,

    /// Delay in milliseconds between consecutive probes
    #[arg(short = 'i', long, default_value_t = 500)]
    interval_ms: u64,

    /// Timeout in milliseconds per probe
    #[arg(short = 't', long, default_value_t = 2000)]
    timeout_ms: u64,

    /// Perform RFC 3489 / RFC 5780 NAT mapping behavior classification test
    #[arg(long)]
    nat_test: bool,

    /// Output full report in JSON format
    #[arg(long)]
    json: bool,

    /// Suppress per-probe console output
    #[arg(short, long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = PingConfig {
        server: cli.server,
        secondary_server: cli.secondary,
        count: cli.count,
        interval_ms: cli.interval_ms,
        timeout_ms: cli.timeout_ms,
        nat_test: cli.nat_test,
        quiet: cli.quiet || cli.json,
    };

    let report = run_rtcping(config).await?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("\n{}", "=== WebRTC STUN Probe Summary ===".bold());
        println!("  Target server:      {} ({})", report.server.cyan(), report.target_addr);
        if let Some(ref sw) = report.software {
            println!("  Server software:    {}", sw.yellow());
        }
        if let Some(ref candidate) = report.reflexive_addr {
            println!("  Public candidate:   {}", candidate.to_string().green().bold());
        }
        println!(
            "  Probes:             {} sent, {} received ({:.1}% packet loss)",
            report.probes_sent,
            report.probes_received,
            report.loss_pct
        );
        if report.probes_received > 0 {
            println!("  Round-trip time:    min: {:.2} ms | avg: {:.2} ms | max: {:.2} ms | stddev: {:.2} ms",
                report.min_rtt_ms, report.avg_rtt_ms, report.max_rtt_ms, report.stddev_rtt_ms);
        }
        if let Some(ref nat) = report.nat_type {
            println!("  NAT classification: {}", nat.bold().magenta());
        }
    }

    if report.probes_received == 0 {
        std::process::exit(1);
    }

    Ok(())
}
