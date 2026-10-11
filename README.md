# rtcping

WebRTC STUN connectivity tester, NAT traversal classifier, and reflexive candidate latency benchmark.

`rtcping` probes STUN and TURN servers (RFC 5389 / RFC 8489 / RFC 3489) directly from the command line without needing a web browser or JavaScript runtime. It discovers public reflexive ICE candidates, benchmarks STUN round-trip latency and packet loss, and classifies network NAT mapping behavior.

## Features

- **STUN Connectivity & RTT Benchmarking**:
  - Sends binary RFC 5389 STUN Binding Requests over UDP.
  - Measures minimum, mean, maximum, and standard deviation round-trip time (RTT).
  - Tracks packet loss percentages across repeated probe sequences.
- **Reflexive Candidate Discovery**:
  - Decodes `XOR-MAPPED-ADDRESS` (RFC 5389 Section 15.2) and legacy `MAPPED-ADDRESS` (RFC 3489) attributes.
  - Reports your public IP address and port mapping as seen by upstream peers.
  - Extracts server software description attributes (`SOFTWARE`).
- **NAT Mapping Behavior Classification (`--nat-test`)**:
  - Evaluates whether your network interface is behind:
    - **Open Internet / Direct**: Public IP directly assigned (no NAT).
    - **Endpoint-Independent Mapping (Cone NAT)**: Port mapping is preserved across destinations (P2P WebRTC friendly).
    - **Address-Dependent / Symmetric NAT**: Port mapping varies per destination (requires TURN relay).
- **Automation & Scripting**:
  - Emits full JSON reports (`--json`) for automated CI/CD network health checks and deployment gates.
  - Exits with non-zero status code if all probes fail or time out.

## Installation

```bash
cargo install --path .
```

## Quick Start

### 1. Probe Google's Public STUN Server

```bash
rtcping stun.l.google.com:19302
```

### 2. High-Frequency Latency Benchmark

```bash
rtcping stun:stun.cloudflare.com:3478 --count 10 --interval-ms 200
```

### 3. Test NAT Mapping Behavior for WebRTC P2P Feasibility

```bash
rtcping stun.l.google.com:19302 --nat-test
```

### 4. Machine-Readable JSON Output for CI/CD Gates

```bash
rtcping stun:turn.mycompany.com:3478 --json
```

## Command-Line Options

```text
Usage: rtcping [OPTIONS] [SERVER]

Arguments:
  [SERVER]  STUN server address or URI [default: stun.l.google.com:19302]

Options:
      --secondary <SERVER>      Secondary STUN server for NAT classification test
  -c, --count <COUNT>           Number of probes to send [default: 5]
  -i, --interval-ms <MS>        Delay in milliseconds between consecutive probes [default: 500]
  -t, --timeout-ms <MS>         Timeout in milliseconds per probe [default: 2000]
      --nat-test                Perform RFC 3489/5780 NAT mapping classification test
      --json                    Output full report in JSON format
  -q, --quiet                   Suppress per-probe console output
  -h, --help                    Print help
  -V, --version                 Print version
```

## Status

Fully functional and verified. Binary RFC 5389 message construction, XOR-MAPPED-ADDRESS decoding, IPv4/IPv6 support, RTT percentile statistics, packet loss tracking, and NAT mapping classification are implemented and verified by automated unit and live UDP socket integration test suites.
