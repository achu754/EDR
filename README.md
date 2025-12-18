# EDR Agent

A lightweight, production-grade endpoint detection and response (EDR) monitoring agent for Windows, written in Rust.

## Overview

EDR Agent is a defensive security monitoring tool that continuously collects security-relevant telemetry from Windows endpoints. It monitors process creation, network connections, and persistence mechanisms, storing events in a local SQLite database and JSONL logs for analysis.

### Why Rust?

This project uses **Rust** for several critical reasons:

- **Memory Safety**: Zero-cost abstractions and compile-time guarantees prevent common vulnerabilities in security tooling
- **Performance**: No garbage collection pauses during continuous monitoring; native performance for system-level operations
- **Windows Integration**: Excellent `windows-rs` crate provides safe, idiomatic bindings to Win32 APIs (ETW, WMI, Registry, etc.)
- **Strong Ecosystem**: Mature libraries for async I/O (tokio), serialization (serde), databases (sqlx), and CLI (clap)
- **Production Quality**: Trusted by security vendors including CrowdStrike and Microsoft Defender

## Features

### Monitoring Capabilities

- **Process Monitoring**
  - Timestamp, PID, Parent PID
  - Image path and command line
  - Username context
  - WMI-based event collection

- **Network Monitoring**
  - TCP/UDP connections mapped to processes
  - Local and remote IP/port information
  - Connection state tracking
  - Windows IP Helper API integration

- **Persistence Monitoring**
  - Registry Run keys (HKLM/HKCU)
  - Startup folders (system and user)
  - Change detection for autoruns

### Detection Engine

Built-in hunt rules for common attack techniques:

1. **Suspicious PowerShell**: Detects encoded commands, download cradles (DownloadString), IEX, hidden windows, and execution policy bypasses
2. **LOLBins (Living Off The Land Binaries)**: Identifies abuse of legitimate Windows utilities (rundll32, regsvr32, mshta, wmic, bitsadmin, certutil, etc.)
3. **Suspicious Parent-Child Relationships**: Flags unusual process spawning (e.g., Office applications launching PowerShell/cmd)

### Data Storage

- **SQLite Database**: Structured storage with indexed queries
- **JSONL Logs**: Line-delimited JSON for easy ingestion into SIEM/analysis tools

## Installation

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- Rust toolchain (stable) - [Install from rustup.rs](https://rustup.rs/)
- Administrator privileges (recommended for full visibility)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/edr-agent.git
cd edr-agent

# Build release binary
cargo build --release

# Binary will be at: target/release/agent.exe
```

## Configuration

Edit `config.yaml` to customize agent behavior:

```yaml
log_level: info  # trace, debug, info, warn, error

database:
  path: "./edr_events.db"

jsonl_log:
  enabled: true
  path: "./events.jsonl"

collectors:
  process:
    enabled: true
    poll_interval: 5  # seconds

  network:
    enabled: true
    poll_interval: 10

  persistence:
    enabled: true
    poll_interval: 30
    watch_paths:
      - "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
      - "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    watch_registry:
      - "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      - "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      - "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      - "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

hunts:
  enabled: true
  auto_hunt: true  # Run hunts automatically on new events
```

## Usage

### Start the Agent

```bash
agent start
```

The agent runs continuously until stopped with `Ctrl+C`. It will:
- Monitor for security events in the background
- Write events to SQLite database
- Append to JSONL log file
- Run auto-hunt rules if enabled

### Check Status

```bash
agent status
```

Output:
```
═══════════════════════════════════════
        EDR Agent Status
═══════════════════════════════════════
Database: ./edr_events.db

Event Counts:
  Process events:     1523
  Network events:     847
  Persistence events: 12
  Hunt matches:       7

Collectors:
  Process:     enabled
  Network:     enabled
  Persistence: enabled

Hunts:
  Enabled:     yes
  Auto-hunt:   yes
═══════════════════════════════════════
```

### Export Events

Export events to JSONL (default):
```bash
agent export --since 24h --format jsonl
```

Export to CSV:
```bash
agent export --since 7d --format csv > events.csv
```

Time formats:
- `24h` - Last 24 hours
- `7d` - Last 7 days
- `1w` - Last week

### Run Hunts

Execute a specific hunt rule:
```bash
agent hunt --rule suspicious-powershell
agent hunt --rule lolbins
agent hunt --rule suspicious-parent-child
```

Example output:
```
═══════════════════════════════════════
     Running Hunt: suspicious-powershell
═══════════════════════════════════════

Found 3 matches:

Match #1:
  Timestamp:   2025-12-18T10:23:45Z
  Rule:        suspicious-powershell
  Event Type:  process
  Event ID:    1523
  Description: Suspicious PowerShell detected: encoded command (-enc/-encodedcommand), hidden window (-WindowStyle Hidden) - Command: powershell.exe -w hidden -enc SGVsbG8gV29ybGQ=

...
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed system design.

### High-Level Components

```
┌─────────────────────────────────────────────────────┐
│                    CLI Layer                        │
│  (start, status, export, hunt commands)             │
└─────────────────────────┬───────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
┌───────▼──────────┐              ┌─────────▼─────────┐
│   Collectors     │              │   Hunt Engine     │
│  - Process       │              │  - Detection      │
│  - Network       │              │    Rules          │
│  - Persistence   │              │  - Auto-hunt      │
└────────┬─────────┘              └─────────┬─────────┘
         │                                   │
         └────────────┬──────────────────────┘
                      │
              ┌───────▼───────┐
              │   Database    │
              │   (SQLite)    │
              └───────┬───────┘
                      │
              ┌───────▼───────┐
              │  JSONL Logs   │
              └───────────────┘
```

### Event Flow

1. **Collectors** poll Windows APIs (WMI, IP Helper, Registry) at configured intervals
2. Events are stored in **SQLite** database with indices for fast queries
3. Events are appended to **JSONL** log file if enabled
4. **Hunt Engine** evaluates events against detection rules (real-time if auto-hunt is enabled)
5. Hunt matches are stored and can be queried via CLI

## Data Schema

See [docs/data_schema.md](docs/data_schema.md) for complete database schema.

### Process Events
```sql
CREATE TABLE process_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    parent_pid INTEGER NOT NULL,
    image_path TEXT NOT NULL,
    command_line TEXT NOT NULL,
    username TEXT NOT NULL
);
```

### Network Events
```sql
CREATE TABLE network_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    local_addr TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_addr TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL
);
```

### Persistence Events
```sql
CREATE TABLE persistence_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    persistence_type TEXT NOT NULL,  -- "registry" or "filesystem"
    location TEXT NOT NULL,
    value_name TEXT,
    value_data TEXT NOT NULL
);
```

### Hunt Matches
```sql
CREATE TABLE hunt_matches (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    description TEXT NOT NULL
);
```

## Testing

Run unit tests:
```bash
cargo test
```

Run tests with output:
```bash
cargo test -- --nocapture
```

Test coverage includes:
- Hunt rule detection logic
- Suspicious PowerShell patterns
- LOLBin detection
- Parent-child relationship analysis

## Limitations

### Current Implementation

- **Polling-based collection**: Process and network collectors use polling rather than pure event-driven collection (ETW/WMI event subscriptions would require more complex setup)
- **Username detection**: Simplified username retrieval; production implementation would use `GetTokenInformation` or WMI `GetOwner()`
- **Network mapping**: Best-effort PID-to-connection mapping via Windows IP Helper API; some short-lived connections may be missed
- **Administrator privileges**: While the agent can run as a regular user, some collectors may have limited visibility without admin rights

### Permissions

The agent will warn if admin privileges are needed but not available. Some operations (e.g., reading certain registry keys, enumerating all processes) require elevated privileges.

### Future Work

- **ETW-based process monitoring**: Real-time event subscription via Event Tracing for Windows
- **Code signing verification**: Add digital signature checks for executables (Authenticode)
- **File hash tracking**: SHA-256 hashing for persistence mechanism files
- **Network flow enrichment**: GeoIP lookups, reputation scoring
- **Alerting**: Email/webhook notifications for critical detections
- **GUI dashboard**: Web-based frontend for event browsing and hunt management

## Threat Model

See [docs/threat_model.md](docs/threat_model.md) for security considerations.

### What This Tool Defends Against

- Living off the land attacks (LOLBins)
- Fileless malware using PowerShell
- Malicious macros in Office documents
- Persistence mechanism establishment
- Suspicious lateral movement patterns

### What This Tool Does NOT Defend Against

- Kernel-mode rootkits (operates in user-mode only)
- Direct memory injection techniques (no memory scanning)
- Anti-debugging or VM-aware malware designed to detect monitoring
- Zero-day exploits without behavioral indicators

## Security Notice

**This is a defensive monitoring tool for authorized use only.**

- Only deploy on systems you own or have explicit permission to monitor
- Ensure compliance with organizational security policies and legal requirements
- This tool does NOT include any offensive capabilities
- Data collected may contain sensitive information; secure the SQLite database and logs appropriately

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes with clear messages
4. Add tests for new functionality
5. Run `cargo fmt` and `cargo clippy` before submitting
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by production EDR solutions (CrowdStrike, Microsoft Defender, SentinelOne)
- Detection rules based on MITRE ATT&CK framework
- Windows API bindings via the excellent `windows-rs` crate

## Support

For issues, questions, or feature requests, please open a GitHub issue.

---

**Built with Rust for security, performance, and reliability.**
