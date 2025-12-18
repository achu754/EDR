# EDR Agent Data Schema

This document describes the data structures and database schema used by the EDR Agent.

## Database Overview

**Technology**: SQLite 3
**Location**: Configurable in `config.yaml` (default: `./edr_events.db`)
**Access Pattern**: Single-writer (agent), multiple-readers (CLI queries)

## Schema Version

**Current Version**: 1.0
**Migration Strategy**: Idempotent `CREATE TABLE IF NOT EXISTS` statements

## Tables

### 1. process_events

Stores process creation events.

#### Schema

```sql
CREATE TABLE process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    parent_pid INTEGER NOT NULL,
    image_path TEXT NOT NULL,
    command_line TEXT NOT NULL,
    username TEXT NOT NULL
);

CREATE INDEX idx_process_timestamp ON process_events(timestamp);
CREATE INDEX idx_process_pid ON process_events(pid);
```

#### Columns

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `timestamp` | TEXT | ISO 8601 timestamp (UTC), e.g., `2025-12-18T10:23:45.123Z` |
| `pid` | INTEGER | Process ID (Windows PID) |
| `parent_pid` | INTEGER | Parent process ID (PPID) |
| `image_path` | TEXT | Full path to executable, e.g., `C:\Windows\System32\cmd.exe` |
| `command_line` | TEXT | Complete command line with arguments |
| `username` | TEXT | Username context (domain\user or MACHINE\user), "Unknown" if unavailable |

#### Example Data

```sql
INSERT INTO process_events VALUES (
    1,
    '2025-12-18T10:23:45.123Z',
    1234,
    5678,
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    'powershell.exe -enc SGVsbG8gV29ybGQ=',
    'DESKTOP-ABC123\user'
);
```

#### Indices

- **idx_process_timestamp**: Optimizes time-range queries (`WHERE timestamp >= ?`)
- **idx_process_pid**: Optimizes PID lookups for parent-child relationship analysis

#### Typical Queries

```sql
-- Get recent process events
SELECT * FROM process_events
WHERE timestamp >= '2025-12-18T00:00:00Z'
ORDER BY timestamp DESC;

-- Find processes by image name
SELECT * FROM process_events
WHERE image_path LIKE '%powershell.exe';

-- Find child processes of a specific PID
SELECT * FROM process_events
WHERE parent_pid = 1234;
```

---

### 2. network_events

Stores network connection events mapped to processes.

#### Schema

```sql
CREATE TABLE network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    local_addr TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_addr TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL
);

CREATE INDEX idx_network_timestamp ON network_events(timestamp);
CREATE INDEX idx_network_pid ON network_events(pid);
```

#### Columns

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `timestamp` | TEXT | ISO 8601 timestamp (UTC) when connection was first observed |
| `pid` | INTEGER | Process ID that owns the connection |
| `local_addr` | TEXT | Local IP address (IPv4 currently, IPv6 future) |
| `local_port` | INTEGER | Local port number |
| `remote_addr` | TEXT | Remote IP address, `0.0.0.0` for UDP listening sockets |
| `remote_port` | INTEGER | Remote port number, `0` for UDP listening sockets |
| `protocol` | TEXT | Protocol: `TCP` or `UDP` |
| `state` | TEXT | Connection state (see below) |

#### Connection States

**TCP States**:
- `CLOSED`, `LISTEN`, `SYN_SENT`, `SYN_RCVD`, `ESTABLISHED`
- `FIN_WAIT1`, `FIN_WAIT2`, `CLOSE_WAIT`, `CLOSING`
- `LAST_ACK`, `TIME_WAIT`, `DELETE_TCB`

**UDP States**:
- `LISTENING` (UDP is connectionless, so state is always LISTENING)

#### Example Data

```sql
-- TCP connection
INSERT INTO network_events VALUES (
    1,
    '2025-12-18T10:24:12.456Z',
    1234,
    '192.168.1.100',
    49152,
    '93.184.216.34',
    443,
    'TCP',
    'ESTABLISHED'
);

-- UDP listening socket
INSERT INTO network_events VALUES (
    2,
    '2025-12-18T10:24:15.789Z',
    5678,
    '0.0.0.0',
    53,
    '0.0.0.0',
    0,
    'UDP',
    'LISTENING'
);
```

#### Indices

- **idx_network_timestamp**: Optimizes time-range queries
- **idx_network_pid**: Optimizes process-to-connection lookups

#### Typical Queries

```sql
-- Get outbound connections (non-loopback, non-zero remote)
SELECT * FROM network_events
WHERE remote_addr != '0.0.0.0'
  AND remote_addr NOT LIKE '127.%'
  AND protocol = 'TCP'
  AND state = 'ESTABLISHED';

-- Find connections by process
SELECT * FROM network_events
WHERE pid = 1234;

-- Detect unusual ports
SELECT DISTINCT remote_port, COUNT(*) as count
FROM network_events
WHERE protocol = 'TCP'
GROUP BY remote_port
ORDER BY count DESC;
```

---

### 3. persistence_events

Stores changes to autorun/persistence mechanisms.

#### Schema

```sql
CREATE TABLE persistence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    persistence_type TEXT NOT NULL,
    location TEXT NOT NULL,
    value_name TEXT,
    value_data TEXT NOT NULL
);

CREATE INDEX idx_persistence_timestamp ON persistence_events(timestamp);
```

#### Columns

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `timestamp` | TEXT | ISO 8601 timestamp (UTC) when change was detected |
| `persistence_type` | TEXT | Type: `registry` or `filesystem` |
| `location` | TEXT | Registry key path or filesystem directory path |
| `value_name` | TEXT | Registry value name (NULL for filesystem events) |
| `value_data` | TEXT | Registry value data or full file path |

#### Persistence Types

**Registry** (`persistence_type = 'registry'`):
- `location`: Registry key path, e.g., `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `value_name`: Registry value name, e.g., `MyApp`
- `value_data`: Value data (typically executable path)

**Filesystem** (`persistence_type = 'filesystem'`):
- `location`: Directory path, e.g., `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
- `value_name`: NULL
- `value_data`: Full path to file, e.g., `C:\...\Startup\malware.lnk`

#### Example Data

```sql
-- Registry persistence
INSERT INTO persistence_events VALUES (
    1,
    '2025-12-18T10:25:30.123Z',
    'registry',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
    'UpdateCheck',
    'C:\Users\user\AppData\Local\Temp\update.exe'
);

-- Filesystem persistence
INSERT INTO persistence_events VALUES (
    2,
    '2025-12-18T10:26:45.456Z',
    'filesystem',
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
    NULL,
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\startup.bat'
);
```

#### Indices

- **idx_persistence_timestamp**: Optimizes time-range queries

#### Typical Queries

```sql
-- Get all persistence changes in last 24 hours
SELECT * FROM persistence_events
WHERE timestamp >= datetime('now', '-1 day');

-- Find registry-based persistence
SELECT * FROM persistence_events
WHERE persistence_type = 'registry';

-- Search for specific executable
SELECT * FROM persistence_events
WHERE value_data LIKE '%malware.exe%';
```

---

### 4. hunt_matches

Stores detection rule matches (behavioral alerts).

#### Schema

```sql
CREATE TABLE hunt_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    description TEXT NOT NULL
);

CREATE INDEX idx_hunt_timestamp ON hunt_matches(timestamp);
```

#### Columns

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `timestamp` | TEXT | ISO 8601 timestamp (UTC) when detection occurred |
| `rule_name` | TEXT | Name of detection rule that triggered |
| `event_type` | TEXT | Type of original event: `process`, `network`, or `persistence` |
| `event_id` | INTEGER | Foreign key to original event (e.g., `process_events.id`) |
| `description` | TEXT | Human-readable description of detection with context |

#### Rule Names

Current built-in rules:
- `suspicious-powershell`: PowerShell abuse patterns
- `lolbins`: Living Off The Land Binaries
- `suspicious-parent-child`: Unusual process relationships

#### Example Data

```sql
INSERT INTO hunt_matches VALUES (
    1,
    '2025-12-18T10:23:50.123Z',
    'suspicious-powershell',
    'process',
    1,
    'Suspicious PowerShell detected: encoded command (-enc/-encodedcommand), hidden window (-WindowStyle Hidden) - Command: powershell.exe -w hidden -enc SGVsbG8gV29ybGQ='
);
```

#### Indices

- **idx_hunt_timestamp**: Optimizes time-range queries for recent alerts

#### Typical Queries

```sql
-- Get recent detections
SELECT * FROM hunt_matches
WHERE timestamp >= datetime('now', '-1 day')
ORDER BY timestamp DESC;

-- Get detections for specific rule
SELECT * FROM hunt_matches
WHERE rule_name = 'suspicious-powershell';

-- Join with original process event
SELECT
    hm.timestamp,
    hm.rule_name,
    hm.description,
    pe.pid,
    pe.image_path,
    pe.command_line
FROM hunt_matches hm
JOIN process_events pe ON hm.event_id = pe.id
WHERE hm.event_type = 'process';
```

---

## Data Types

### Timestamp Format

**Standard**: ISO 8601 (UTC)
**Format**: `YYYY-MM-DDTHH:MM:SS.sssZ`
**Example**: `2025-12-18T10:23:45.123Z`

**Rationale**:
- SQLite TEXT datatype with ISO 8601 allows natural sorting and comparison
- UTC eliminates timezone ambiguity
- Parseable by all major languages and tools

**Rust Representation**: `chrono::DateTime<Utc>`

### Integer Types

All integers stored as SQLite `INTEGER` (64-bit signed).

**Conversions**:
- Windows PID (DWORD/u32) → INTEGER
- Ports (u16) → INTEGER
- IDs (i64) → INTEGER

### Text Encoding

**Storage**: UTF-8
**Source**: Windows APIs return UTF-16, converted to UTF-8 by Rust

**Escaping**:
- SQL injection prevented by parameterized queries (sqlx)
- Special characters in command lines preserved as-is

---

## JSONL Log Format

In addition to SQLite, events are written to a JSONL (JSON Lines) log file.

### Process Event JSONL

```json
{
  "id": 1,
  "timestamp": "2025-12-18T10:23:45.123Z",
  "pid": 1234,
  "parent_pid": 5678,
  "image_path": "C:\\Windows\\System32\\cmd.exe",
  "command_line": "cmd.exe /c dir",
  "username": "DESKTOP-ABC123\\user"
}
```

### Network Event JSONL

```json
{
  "id": 1,
  "timestamp": "2025-12-18T10:24:12.456Z",
  "pid": 1234,
  "local_addr": "192.168.1.100",
  "local_port": 49152,
  "remote_addr": "93.184.216.34",
  "remote_port": 443,
  "protocol": "TCP",
  "state": "ESTABLISHED"
}
```

### Persistence Event JSONL

```json
{
  "id": 1,
  "timestamp": "2025-12-18T10:25:30.123Z",
  "persistence_type": "registry",
  "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "value_name": "UpdateCheck",
  "value_data": "C:\\Users\\user\\AppData\\Local\\Temp\\update.exe"
}
```

### Parsing JSONL

**Command Line (jq)**:
```bash
# Get all PowerShell events
cat events.jsonl | jq 'select(.image_path | contains("powershell.exe"))'

# Count events by type
cat events.jsonl | jq -r 'if .pid then "process" elif .protocol then "network" else "persistence" end' | sort | uniq -c
```

**Python**:
```python
import json

with open('events.jsonl', 'r') as f:
    for line in f:
        event = json.loads(line)
        if 'command_line' in event and 'powershell' in event['command_line']:
            print(event)
```

---

## Schema Migration

### Current Approach

Migrations are applied at agent startup via `database/migrations.rs`.

**Strategy**: Idempotent DDL
```rust
sqlx::query("CREATE TABLE IF NOT EXISTS process_events ...")
    .execute(pool)
    .await?;
```

### Future Migrations

For schema changes (e.g., adding columns, tables):

1. Increment schema version
2. Add migration function: `run_migration_v2()`
3. Check current schema version in database
4. Apply incremental migrations

**Example**:
```sql
-- Add schema_version table
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Check version
SELECT MAX(version) FROM schema_version;

-- Apply migration
ALTER TABLE process_events ADD COLUMN integrity_level TEXT;
INSERT INTO schema_version VALUES (2, datetime('now'));
```

---

## Performance Characteristics

### Insert Performance

**Typical Rate**: 100-1000 events/second (untuned)

**Optimization**:
- Use transactions for batch inserts
- Asynchronous writes via sqlx
- WAL mode for concurrent readers: `PRAGMA journal_mode=WAL;`

### Query Performance

**Indexed Queries**: O(log n) via B-tree indices
- Timestamp range queries: Fast (indexed)
- PID lookups: Fast (indexed)

**Full Table Scans**: O(n)
- Command line text search: Slow without FTS (consider SQLite FTS5)

### Database Size

**Estimate**:
- Process event: ~500 bytes average
- Network event: ~200 bytes average
- Persistence event: ~300 bytes average

**Example**: 1 million process events ≈ 500 MB

**Mitigation**:
- Implement event retention policy (e.g., delete events older than 30 days)
- Use `VACUUM` to reclaim space

---

## Backup and Recovery

### Backup

**Method 1: File Copy**
```bash
# Stop agent, then copy database file
copy edr_events.db edr_events.backup.db
```

**Method 2: SQLite Backup API**
```sql
sqlite3 edr_events.db ".backup edr_events.backup.db"
```

**Method 3: Export to SQL**
```sql
sqlite3 edr_events.db ".dump" > backup.sql
```

### Recovery

**From Backup**:
```bash
copy edr_events.backup.db edr_events.db
```

**From SQL Dump**:
```bash
sqlite3 edr_events.db < backup.sql
```

### JSONL as Backup

JSONL logs provide an append-only audit trail that can reconstruct events if database is corrupted.

**Reconstruction**:
```python
import json
import sqlite3

conn = sqlite3.connect('recovered.db')
cursor = conn.cursor()

with open('events.jsonl', 'r') as f:
    for line in f:
        event = json.loads(line)
        # Insert into appropriate table based on event fields
        if 'command_line' in event:
            cursor.execute("INSERT INTO process_events ...")
        # ... handle other event types

conn.commit()
```

---

## Data Retention

### Recommended Policy

**Production**:
- Retain events for 30-90 days in local database
- Archive older events to long-term storage (S3, network share)
- Retain JSONL logs for 1 year

**Development/Testing**:
- Retain for 7 days or until disk space is needed

### Implementation

**Manual**:
```sql
DELETE FROM process_events WHERE timestamp < datetime('now', '-30 days');
VACUUM;
```

**Automated** (future enhancement):
- Add retention configuration to `config.yaml`
- Background task to prune old events
- Export to archive before deletion

---

## Security Considerations

### Sensitive Data

**Risk**: Events contain sensitive information
- Command lines may include passwords, tokens, API keys
- Usernames reveal account information
- Network connections show internal topology

**Mitigation**:
- Restrict file system permissions on database and logs
- Consider encryption at rest (SQLCipher)
- Implement access controls for query interface
- Redact sensitive patterns (e.g., regex for API keys)

### SQL Injection

**Protection**: Parameterized queries via sqlx
```rust
// Safe: parameterized query
sqlx::query("SELECT * FROM process_events WHERE pid = ?")
    .bind(pid)
    .fetch_all(pool).await?;

// NEVER: string concatenation (vulnerable)
// let query = format!("SELECT * FROM process_events WHERE pid = {}", pid);
```

---

## References

- SQLite Documentation: https://www.sqlite.org/docs.html
- ISO 8601 Timestamp Standard: https://en.wikipedia.org/wiki/ISO_8601
- JSONL Specification: https://jsonlines.org/
- SQLite FTS5 (Full-Text Search): https://www.sqlite.org/fts5.html
