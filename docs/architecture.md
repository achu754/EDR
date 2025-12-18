# EDR Agent Architecture

## Overview

The EDR Agent is designed as a modular, event-driven monitoring system with clean separation of concerns. The architecture prioritizes reliability, performance, and maintainability.

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLI Interface                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │  start   │  │  status  │  │  export  │  │   hunt   │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└────────────────────────┬─────────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌─────────────────────┐         ┌──────────────────┐
│  Collector Manager  │         │   Hunt Engine    │
│                     │         │                  │
│  ┌──────────────┐  │         │  ┌────────────┐  │
│  │   Process    │──┼────────▶│  │   Rules    │  │
│  │  Collector   │  │         │  │  Evaluator │  │
│  └──────────────┘  │         │  └────────────┘  │
│                     │         │                  │
│  ┌──────────────┐  │         │  ┌────────────┐  │
│  │   Network    │──┼────────▶│  │  Matcher   │  │
│  │  Collector   │  │         │  │  Storage   │  │
│  └──────────────┘  │         │  └────────────┘  │
│                     │         │                  │
│  ┌──────────────┐  │         └──────────────────┘
│  │ Persistence  │  │                  │
│  │  Collector   │  │                  │
│  └──────────────┘  │                  │
│                     │                  │
└─────────┬───────────┘                  │
          │                              │
          │      Event Stream            │
          └──────────┬───────────────────┘
                     │
                     ▼
          ┌──────────────────┐
          │  Event Logger    │
          │  (JSONL Writer)  │
          └──────────────────┘
                     │
          ┌──────────┴───────────┐
          │                      │
          ▼                      ▼
┌──────────────────┐   ┌──────────────────┐
│ SQLite Database  │   │  JSONL Log File  │
│                  │   │                  │
│  - Indexed       │   │  - Append-only   │
│  - Queryable     │   │  - Parseable     │
│  - Transactional │   │  - Line-delim    │
└──────────────────┘   └──────────────────┘
```

## Core Components

### 1. CLI Interface (`cli.rs`)

**Responsibility**: User interaction and command execution

**Commands**:
- `start`: Initialize collectors, event loop, and shutdown handling
- `status`: Query database for event counts and configuration state
- `export`: Extract and format events for external analysis
- `hunt`: Execute detection rules against stored events

**Design Decisions**:
- Uses `clap` for robust argument parsing with auto-generated help
- Async/await throughout for non-blocking I/O operations
- Graceful shutdown via tokio broadcast channels

### 2. Configuration (`config.rs`)

**Responsibility**: Centralized configuration management

**Features**:
- YAML-based configuration file
- Type-safe deserialization with `serde`
- Validation at load time
- Environment-specific overrides possible via environment variables

**Schema**:
```rust
Config
  ├─ log_level: String
  ├─ database: DatabaseConfig
  ├─ jsonl_log: JsonlLogConfig
  ├─ collectors: CollectorsConfig
  │   ├─ process: ProcessCollectorConfig
  │   ├─ network: NetworkCollectorConfig
  │   └─ persistence: PersistenceCollectorConfig
  └─ hunts: HuntsConfig
```

### 3. Collector Manager (`collectors/mod.rs`)

**Responsibility**: Lifecycle management for all collectors

**Architecture**:
- Spawns each enabled collector as a separate tokio task
- Provides broadcast channel for event distribution
- Handles coordinated shutdown across all collectors
- Implements backpressure through bounded channels (capacity: 1000)

**Event Flow**:
```
Collector → CollectorEvent → Broadcast Channel → Event Logger
                                                → Hunt Engine
```

### 4. Process Collector (`collectors/process.rs`)

**Responsibility**: Monitor process creation events

**Implementation**:
- **Primary method**: WMI polling via `wmi` crate
- Polls `Win32_Process` at configured interval (default: 5s)
- Maintains set of known processes to detect new creations
- Future enhancement: ETW subscription for real-time events

**Data Collected**:
- Process ID (PID)
- Parent Process ID (PPID)
- Image path (executable location)
- Command line arguments
- Username context

**Challenges**:
- Username retrieval requires token manipulation (simplified in current impl)
- Short-lived processes may be missed between polls
- ETW would provide more reliable event stream but adds complexity

### 5. Network Collector (`collectors/network.rs`)

**Responsibility**: Map network connections to processes

**Implementation**:
- Uses Windows IP Helper API (`GetExtendedTcpTable`, `GetExtendedUdpTable`)
- Polls connection tables at configured interval (default: 10s)
- Tracks known connections via hash set to detect new connections
- Supports both IPv4 (current) and IPv6 (extensible)

**Data Collected**:
- Process ID
- Local IP:Port
- Remote IP:Port (TCP only; UDP is connectionless)
- Protocol (TCP/UDP)
- Connection state (ESTABLISHED, LISTEN, etc.)

**Limitations**:
- Polling-based: short-lived connections may be missed
- PID mapping is best-effort; race conditions possible
- No packet capture or deep packet inspection

### 6. Persistence Collector (`collectors/persistence.rs`)

**Responsibility**: Detect changes to autorun mechanisms

**Monitored Locations**:

**Registry Keys**:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**Filesystem**:
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
- `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

**Implementation**:
- Polls at configured interval (default: 30s)
- Maintains hash maps of known registry values and files
- Detects additions, modifications, and (implicitly) deletions
- Uses Windows Registry API via `windows-rs` crate

**Change Detection**:
- Registry: Compare value name + value data
- Filesystem: File size as simple hash (could use SHA-256)

### 7. Database Layer (`database/`)

**Responsibility**: Persistent storage and querying

**Technology**: SQLite via `sqlx` crate
- Compile-time checked queries (type safety)
- Connection pooling for concurrency
- Async query execution

**Schema Design**:
- Four main tables: `process_events`, `network_events`, `persistence_events`, `hunt_matches`
- Indices on timestamp and PID columns for query performance
- TEXT-based timestamp storage (ISO 8601) for SQLite compatibility

**Migrations** (`migrations.rs`):
- Idempotent schema creation (`CREATE TABLE IF NOT EXISTS`)
- Index creation for query optimization
- Extensible for future schema changes

**Query Patterns**:
- Time-range queries: `WHERE timestamp >= ?`
- Event counting: `SELECT COUNT(*) FROM ...`
- Hunt matching: Join process events with hunt results

### 8. Hunt Engine (`hunts/`)

**Responsibility**: Behavioral detection and alerting

**Detection Modes**:
1. **Real-time**: Auto-hunt on new events (if enabled)
2. **Batch**: Run hunts on historical data via CLI

**Built-in Rules** (`rules.rs`):

**1. Suspicious PowerShell**
- Detects: `-enc`, `-encodedcommand`, `DownloadString`, `IEX`, `-w hidden`, `-nop`, `-ep bypass`
- MITRE: T1059.001 (PowerShell), T1027 (Obfuscated Files)

**2. LOLBins (Living Off The Land Binaries)**
- Detects: `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wmic.exe`, `bitsadmin.exe`, `certutil.exe`, etc.
- Context-aware: Checks for suspicious arguments (e.g., `certutil -urlcache`)
- MITRE: T1218.* (Signed Binary Proxy Execution)

**3. Suspicious Parent-Child**
- Detects: Office apps spawning PowerShell/cmd/scripting engines
- Examples: `winword.exe → powershell.exe`, `excel.exe → cmd.exe`
- MITRE: T1566.001 (Spearphishing Attachment)

**Rule Architecture**:
```rust
pub fn check_rule(event: &ProcessEvent) -> Option<HuntMatch>
```

Each rule:
- Takes an event as input
- Returns `Some(HuntMatch)` if suspicious, `None` otherwise
- Includes human-readable description of detection

**Hunt Match Storage**:
- Matches stored in `hunt_matches` table
- Linked to original event via `event_id`
- Queryable for incident response

### 9. Event Logger

**Responsibility**: Write events to JSONL log file

**Implementation**:
- Spawned as tokio task consuming event broadcast channel
- Appends to log file in append-only mode
- Each event is a single JSON object per line (JSONL format)

**Format**:
```json
{"id":1,"timestamp":"2025-12-18T10:23:45Z","pid":1234,"parent_pid":5678,"image_path":"C:\\Windows\\System32\\cmd.exe","command_line":"cmd.exe /c dir","username":"user"}
```

**Benefits**:
- Easy to parse with `jq`, Python, or SIEM tools
- Append-only: no corruption risk
- Human-readable for debugging

## Concurrency Model

### Async Runtime: Tokio

**Why Tokio?**:
- Industry-standard async runtime for Rust
- Efficient task scheduling (work-stealing)
- Mature ecosystem (timers, channels, file I/O)

### Task Structure

```
Main Task
  ├─ Collector Manager Task
  │   ├─ Process Collector Task
  │   ├─ Network Collector Task
  │   └─ Persistence Collector Task
  ├─ Event Logger Task
  └─ Signal Handler (Ctrl+C)
```

### Communication

**Broadcast Channels**:
- Shutdown signal: `broadcast::channel<()>`
- Events: `broadcast::channel<CollectorEvent>`

**Benefits**:
- Non-blocking communication
- Multiple subscribers supported
- Graceful shutdown coordination

## Error Handling

**Strategy**: Fail gracefully, log errors, continue operation

**Patterns**:
- Collectors log errors but don't crash the agent
- Database errors are logged and operation continues
- Invalid configuration causes startup failure (fail-fast)

**Error Types**:
- `anyhow::Result` for application errors (flexible, context-rich)
- `thiserror` for domain-specific error types (unused currently, but extensible)

## Performance Considerations

### Memory

**Bounded Channels**: Prevent memory exhaustion under load
- Event channel capacity: 1000
- Backpressure if producers exceed consumer rate

**Connection Tracking**: Hash sets for deduplication
- O(1) lookups for known connections/processes
- Periodic cleanup could be added for long-running agents

### CPU

**Polling Intervals**: Configurable to balance responsiveness vs. CPU usage
- Process: 5s (can detect new processes within 5 seconds)
- Network: 10s (network connections change frequently)
- Persistence: 30s (autoruns change infrequently)

**Database Indices**: Optimize common query patterns
- Timestamp indices for time-range queries
- PID indices for process lookups

### I/O

**Async I/O**: Non-blocking database and file operations via `sqlx` and `tokio::fs`

**Batch Writes**: Could be added for JSONL log writes (currently individual writes)

## Security Considerations

### Privilege Requirements

**Admin privileges recommended for**:
- Full process enumeration (protected processes)
- System-wide registry access
- All users' startup folders

**Graceful degradation**:
- Agent runs as normal user but with reduced visibility
- Warnings logged for permission-denied scenarios

### Data Protection

**Database Security**:
- SQLite file should have restrictive ACLs (not implemented; OS-level)
- No encryption at rest (future: SQLCipher extension)

**Log File Security**:
- JSONL file contains sensitive command lines and usernames
- Should be protected with filesystem ACLs

### Input Validation

**Configuration**:
- YAML parser validates structure
- Invalid paths/intervals rejected at startup

**Windows API Data**:
- Data from Windows APIs trusted (kernel-level source)
- String encoding handled safely (UTF-16 → UTF-8 conversion)

## Extension Points

### Adding New Collectors

1. Implement collector struct in `collectors/`
2. Add configuration to `config.rs`
3. Spawn task in `CollectorManager::start()`
4. Define event type in `CollectorEvent` enum

### Adding New Hunt Rules

1. Add detection function to `hunts/rules.rs`
2. Call from `HuntEngine::check_event()` for real-time detection
3. Call from `HuntEngine::run_hunt()` for batch hunting
4. Add tests to `tests/hunt_tests.rs`

### Adding New Export Formats

1. Add format variant to CLI parser
2. Implement serialization in `cli::export_events()`
3. Example formats: XML, Protobuf, Parquet

## Testing Strategy

### Unit Tests

**Location**: `tests/hunt_tests.rs`, inline tests in `hunts/rules.rs`

**Coverage**:
- Hunt rule logic (positive and negative cases)
- Event pattern matching
- Edge cases (empty strings, special characters)

**Run**: `cargo test`

### Integration Tests

**Future Work**:
- End-to-end collector tests (requires Windows test environment)
- Database migration tests
- CLI command tests

### Fuzzing

**Future Work**:
- Fuzz hunt rules with malformed events
- Fuzz configuration parser

## Deployment

### Installation

1. Build release binary: `cargo build --release`
2. Copy binary and `config.yaml` to deployment location
3. Configure collectors and paths in `config.yaml`
4. Run as Windows service (optional, using NSSM or similar)

### Monitoring

**Health Checks**:
- `agent status` command for event counts
- Check JSONL log file for recent events
- Monitor database file size growth

**Logging**:
- Structured logging via `tracing` crate
- Configurable log level in `config.yaml`
- Output to stdout/stderr (redirect to file or Windows Event Log)

## Future Enhancements

### Short-term

- [ ] ETW-based process monitoring (real-time events)
- [ ] Improved username retrieval (GetTokenInformation)
- [ ] File hashing for persistence mechanisms (SHA-256)
- [ ] Admin privilege detection and warnings

### Medium-term

- [ ] Code signing verification (Authenticode)
- [ ] Network flow enrichment (GeoIP, reputation)
- [ ] Alerting (email, webhook, Windows Event Log)
- [ ] Configuration hot-reload (no restart needed)

### Long-term

- [ ] Web-based dashboard for event browsing
- [ ] Distributed deployment (centralized log aggregation)
- [ ] Machine learning-based anomaly detection
- [ ] Kernel-mode driver for deeper visibility

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Windows API Documentation: https://docs.microsoft.com/en-us/windows/win32/
- Rust Async Book: https://rust-lang.github.io/async-book/
- SQLite Documentation: https://www.sqlite.org/docs.html
