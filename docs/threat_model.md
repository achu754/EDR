# EDR Agent Threat Model

This document outlines the security considerations, assumptions, and limitations of the EDR Agent.

## Purpose and Scope

### Primary Purpose

The EDR Agent is a **defensive monitoring tool** designed to:
- Detect suspicious process execution patterns
- Identify network connections from potentially malicious processes
- Monitor persistence mechanism establishment
- Provide behavioral telemetry for incident response

### Out of Scope

This tool is **NOT** designed for:
- Active exploitation or offensive security operations
- Circumventing security controls
- Hiding malicious activity
- Enabling unauthorized access

## Security Assumptions

### Deployment Environment

1. **Authorized Deployment**: The agent is deployed on systems you own or have explicit permission to monitor
2. **Trusted Operator**: The operator running the agent has legitimate security monitoring responsibilities
3. **Physical/Logical Access Control**: The host system is protected from unauthorized physical and remote access
4. **OS Integrity**: The underlying Windows OS is not compromised by kernel-mode rootkits
5. **Admin Privileges**: The agent operator has appropriate permissions (ideally Administrator for full visibility)

### Trust Boundaries

```
┌─────────────────────────────────────────────┐
│            Trusted Zone                     │
│  ┌──────────────┐      ┌────────────────┐  │
│  │  EDR Agent   │◄────►│   SQLite DB    │  │
│  │   (Rust)     │      │   (Local File) │  │
│  └──────┬───────┘      └────────────────┘  │
│         │                                   │
│  ┌──────▼───────────────────────────────┐  │
│  │  JSONL Log (Local File)              │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  Windows OS (WMI, Registry, APIs)    │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
             │
             │ Trust Boundary
             │
┌────────────▼──────────────────────────────┐
│         Monitored Processes                │
│  (Potentially Untrusted/Malicious)         │
└────────────────────────────────────────────┘
```

**Trust Boundary**: The agent trusts data from Windows OS APIs but considers monitored processes as potentially malicious.

## Threats Addressed

### 1. Living Off The Land (LOLBins)

**Threat**: Attackers abuse legitimate Windows binaries to evade detection.

**Examples**:
- `certutil.exe` to download payloads
- `bitsadmin.exe` for file transfers
- `rundll32.exe` to execute malicious DLLs
- `mshta.exe` for HTML Application attacks

**Detection**: `lolbins` hunt rule identifies suspicious usage patterns based on command-line arguments.

**Mitigation Effectiveness**: **High** - The agent logs all process executions and flags known LOLBins with suspicious arguments.

**Limitations**:
- Cannot distinguish authorized use (e.g., IT admin running `certutil` legitimately)
- Does not block execution (monitoring only)

**MITRE ATT&CK**: T1218.* (Signed Binary Proxy Execution)

---

### 2. Malicious PowerShell Usage

**Threat**: PowerShell is frequently used for fileless attacks, payload delivery, and post-exploitation.

**Indicators**:
- Encoded commands (`-enc`, `-encodedcommand`)
- Download cradles (`DownloadString`, `IEX`)
- Hidden windows (`-w hidden`)
- Execution policy bypass (`-ep bypass`)

**Detection**: `suspicious-powershell` hunt rule identifies common attack patterns.

**Mitigation Effectiveness**: **High** - Detects most common PowerShell abuse techniques.

**Limitations**:
- Sophisticated attackers can obfuscate differently
- Legitimate automation may trigger false positives

**MITRE ATT&CK**: T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)

---

### 3. Malicious Document Macros

**Threat**: Office documents with malicious macros spawn scripting engines (PowerShell, cmd, wscript).

**Attack Chain**:
1. User opens malicious document (`.docx`, `.xlsx`, `.pptx`)
2. Macro executes and spawns `powershell.exe` or `cmd.exe`
3. Payload is downloaded and executed

**Detection**: `suspicious-parent-child` hunt rule detects Office applications spawning unusual child processes.

**Mitigation Effectiveness**: **High** - Detects most macro-based attacks.

**Limitations**:
- Does not analyze macro content (only behavior)
- Cannot prevent initial document opening

**MITRE ATT&CK**: T1566.001 (Spearphishing Attachment)

---

### 4. Persistence Mechanism Establishment

**Threat**: Attackers establish persistence via registry keys or startup folders to survive reboots.

**Common Techniques**:
- Registry Run keys: `HKLM\...\Run`, `HKCU\...\Run`
- Startup folders: `C:\ProgramData\...\Startup`, `C:\Users\*\...\Startup`

**Detection**: Persistence collector monitors these locations for changes.

**Mitigation Effectiveness**: **Medium** - Detects most common persistence mechanisms.

**Limitations**:
- Does not cover all 200+ Windows persistence techniques (Task Scheduler, Services, WMI subscriptions, etc.)
- Polling-based: 30-second delay in detection

**MITRE ATT&CK**: T1547.001 (Registry Run Keys), T1547.009 (Shortcut Modification)

---

### 5. Network Command & Control (C2)

**Threat**: Malware establishes network connections to attacker-controlled servers.

**Detection**: Network collector logs all TCP/UDP connections with owning process IDs.

**Mitigation Effectiveness**: **Medium** - Provides visibility but requires manual analysis or additional enrichment.

**Limitations**:
- No automatic C2 detection (requires IP reputation lookups, behavioral analysis)
- Polling-based: short-lived connections may be missed
- No packet inspection or protocol analysis

**MITRE ATT&CK**: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)

---

## Threats NOT Addressed

### 1. Kernel-Mode Rootkits

**Description**: Malware operating at kernel level (ring 0) can hide processes, files, and network connections from user-mode monitoring.

**Why Not Addressed**: The EDR Agent operates entirely in user mode and relies on Windows APIs. A kernel rootkit can manipulate API responses.

**Mitigation**: Deploy kernel-mode security solutions (e.g., Microsoft Defender, CrowdStrike Falcon) or implement trusted boot with UEFI Secure Boot and Measured Boot.

---

### 2. Direct Memory Manipulation

**Description**: Process injection, DLL injection, reflective loading, and in-memory-only payloads.

**Why Not Addressed**: The agent does not perform memory scanning or analyze loaded modules.

**Mitigation**: Use tools with memory scanning capabilities (e.g., Volatility, Rekall) or EDR solutions with memory protection features.

**MITRE ATT&CK**: T1055 (Process Injection)

---

### 3. Evasion via Timing Attacks

**Description**: Malware detects monitoring and delays execution or changes behavior.

**Why Not Addressed**: The agent's polling intervals create detection windows (5-30 seconds). Short-lived processes may evade detection.

**Mitigation**: Implement ETW-based event-driven collection for real-time process monitoring.

---

### 4. Anti-Debugging and VM Detection

**Description**: Malware detects virtual machines, sandboxes, or debuggers and alters behavior to evade analysis.

**Why Not Addressed**: The agent does not attempt to hide its presence or spoof system characteristics.

**Mitigation**: Use bare-metal analysis environments or sophisticated anti-evasion techniques.

---

### 5. Encryption and Obfuscation

**Description**: Encrypted C2 traffic (HTTPS, DNS tunneling) and obfuscated payloads.

**Why Not Addressed**:
- Network collector logs connections but does not inspect packet contents
- Hunt rules detect some obfuscation patterns but not all

**Mitigation**: Deploy network traffic analysis (NTA) tools, TLS inspection proxies, or NGFW.

**MITRE ATT&CK**: T1027 (Obfuscated Files), T1573 (Encrypted Channel)

---

### 6. Supply Chain Attacks

**Description**: Compromise of legitimate software used by the organization.

**Why Not Addressed**: The agent trusts signed binaries and does not perform supply chain analysis.

**Mitigation**: Implement application whitelisting, code signing verification, and vendor security assessments.

**MITRE ATT&CK**: T1195 (Supply Chain Compromise)

---

## Agent Security Considerations

### Attack Surface

#### 1. Configuration File

**Risk**: Attacker modifies `config.yaml` to disable collectors or change database location.

**Impact**: Blind spots in monitoring, data loss.

**Mitigation**:
- Protect `config.yaml` with filesystem ACLs (read-only for non-admin users)
- Implement file integrity monitoring for configuration files
- Log configuration changes

#### 2. Database File

**Risk**: Attacker tampers with or deletes `edr_events.db`.

**Impact**: Loss of forensic evidence, false sense of security.

**Mitigation**:
- Protect database file with restrictive ACLs
- Implement tamper detection (file hashing, WORM storage)
- Backup database regularly to secure location
- Enable SQLite write-ahead logging (WAL) for atomic operations

#### 3. JSONL Log File

**Risk**: Attacker appends false events or deletes log entries.

**Impact**: Poisoned telemetry, evidence destruction.

**Mitigation**:
- Protect log file with restrictive ACLs
- Forward logs to centralized SIEM in real-time (future enhancement)
- Implement log signing or HMAC for integrity verification

#### 4. Process Termination

**Risk**: Attacker terminates the agent process.

**Impact**: Monitoring blindness.

**Mitigation**:
- Run agent as a Windows service with automatic restart
- Implement Protected Process Light (PPL) protection (requires kernel driver)
- Monitor agent health from external system

#### 5. Privilege Escalation

**Risk**: Attacker exploits vulnerability in agent code to gain elevated privileges.

**Impact**: Full system compromise.

**Mitigation**:
- Rust's memory safety prevents many vulnerability classes (buffer overflows, use-after-free)
- Run agent with least privilege necessary (not SYSTEM if possible)
- Regular security audits and dependency updates
- Fuzz testing for input validation

---

### Data Privacy and Compliance

#### Sensitive Data Collection

**Data Collected**:
- Command lines (may contain passwords, API keys, PII)
- Usernames (account enumeration risk)
- Network connections (internal topology disclosure)

**Privacy Risks**:
- Unintended capture of sensitive information
- Insider threat (operator with access to database)
- Data breach if database is compromised

**Mitigations**:
1. **Access Controls**: Restrict database and log file access to authorized security personnel only
2. **Encryption at Rest**: Consider SQLCipher or full-disk encryption
3. **Data Minimization**: Configure collectors to only capture necessary events
4. **Retention Policies**: Delete old events to reduce exposure window
5. **Redaction**: Implement pattern-based redaction for common secrets (e.g., regex for API keys)
6. **Compliance**: Ensure deployment complies with GDPR, CCPA, SOC 2, or other applicable regulations

#### Legal Considerations

**Employee Monitoring**: Inform employees of monitoring in accordance with local labor laws and company policy.

**Incident Response**: Ensure proper chain of custody for forensic evidence.

---

### Dependencies and Supply Chain

#### Rust Crates

The agent depends on third-party Rust crates. Vulnerabilities in dependencies could impact security.

**Key Dependencies**:
- `tokio`: Async runtime (critical for agent stability)
- `sqlx`: Database library (SQL injection risk if misused)
- `windows`: Windows API bindings (unsafe code blocks)
- `wmi`: WMI access (COM interop complexity)
- `serde`, `serde_json`: Serialization (parsing vulnerabilities)

**Mitigations**:
1. **Dependency Auditing**: Run `cargo audit` regularly to check for known vulnerabilities
2. **Minimal Dependencies**: Only include necessary crates
3. **Pinned Versions**: Use `Cargo.lock` to ensure reproducible builds
4. **Security Updates**: Monitor security advisories and update promptly
5. **Vendoring**: Consider vendoring dependencies for air-gapped environments

**Example**:
```bash
cargo install cargo-audit
cargo audit
```

---

### Code Security

#### Memory Safety

**Strength**: Rust's ownership model prevents:
- Buffer overflows
- Use-after-free
- Data races

**Unsafe Code**: The agent uses `unsafe` blocks for Windows API calls (e.g., `GetExtendedTcpTable`).

**Risk**: Incorrect unsafe code can introduce vulnerabilities.

**Mitigation**:
- Minimize unsafe code surface area
- Carefully review all `unsafe` blocks
- Use safe abstractions provided by `windows-rs` crate
- Fuzz test unsafe code paths

#### Input Validation

**Inputs**:
- Configuration file (YAML)
- Command-line arguments
- Windows API responses

**Risks**:
- Malformed YAML could cause panic (DoS)
- Large strings from Windows APIs could cause memory exhaustion

**Mitigations**:
- Use `serde_yaml` for safe parsing
- Limit string lengths from Windows APIs
- Handle errors gracefully (no panics in production code)

---

## Deployment Security

### Recommended Deployment Practices

1. **Run as Service**: Use Windows Service or Task Scheduler for automatic startup and restart.

2. **Least Privilege**: Run agent with minimal necessary permissions. Admin recommended but not strictly required.

3. **Secure Storage**:
   ```powershell
   # Restrict access to database and logs
   icacls edr_events.db /grant Administrators:F /inheritance:r
   icacls events.jsonl /grant Administrators:F /inheritance:r
   ```

4. **Network Isolation**: If centralized logging is not used, ensure database and logs are not exposed via network shares.

5. **Monitoring the Monitor**: External system should verify agent is running and collecting events.

6. **Backup and Recovery**: Regular backups of database to secure location.

7. **Incident Response Plan**: Define procedures for investigating hunt matches.

---

## Future Security Enhancements

### Short-Term

- [ ] **Admin Privilege Detection**: Warn user if running without admin and document visibility limitations
- [ ] **Configuration Validation**: More robust validation of paths, intervals, regex patterns
- [ ] **Log Signing**: HMAC or digital signatures for JSONL log entries
- [ ] **Secure Erase**: Implement secure deletion for old events (overwrite before deletion)

### Medium-Term

- [ ] **Encryption at Rest**: Integrate SQLCipher for encrypted database
- [ ] **TLS Support**: Encrypted transmission to centralized SIEM
- [ ] **Code Signing**: Sign release binaries with Authenticode certificate
- [ ] **Rate Limiting**: Prevent log flooding DoS attacks
- [ ] **Redaction Engine**: Pattern-based redaction of sensitive data in command lines

### Long-Term

- [ ] **Protected Process**: Implement PPL protection (requires kernel driver)
- [ ] **Kernel Driver**: Extend visibility with kernel-mode monitoring
- [ ] **Anomaly Detection**: Machine learning for behavioral baselines
- [ ] **Threat Intelligence Integration**: IP/domain reputation lookups

---

## Vulnerability Disclosure

### Reporting Security Issues

If you discover a security vulnerability in the EDR Agent:

1. **Do NOT** open a public GitHub issue
2. Email security contact: [security@example.com]
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested mitigation (if any)

### Response Timeline

- **24 hours**: Acknowledgment of report
- **7 days**: Initial assessment and triage
- **30 days**: Patch development and testing
- **Public disclosure**: Coordinated with reporter after patch release

---

## Compliance Considerations

### GDPR (General Data Protection Regulation)

**Personal Data Collected**: Usernames, command lines (may contain PII)

**Requirements**:
- **Lawful Basis**: Legitimate interest (security monitoring)
- **Data Minimization**: Only collect necessary data
- **Retention Limits**: Delete events after defined period (e.g., 90 days)
- **Access Controls**: Restrict database access to authorized personnel
- **Data Subject Rights**: Provide mechanism to export or delete user's data upon request

### CCPA (California Consumer Privacy Act)

Similar requirements to GDPR for California residents.

### SOC 2 (Service Organization Control)

**Relevant Controls**:
- **CC6.1**: Logical access controls (database ACLs)
- **CC6.6**: Monitoring activities (the agent itself)
- **CC7.2**: System operation monitoring (agent health checks)

### HIPAA (Health Insurance Portability and Accountability Act)

If deployed in healthcare environment, ensure:
- Database contains no PHI (Protected Health Information)
- Redact medical record numbers, patient names from command lines
- Encryption at rest and in transit

---

## Threat Intelligence Integration

### Future Enhancement: IOC Matching

**Indicators of Compromise (IOCs)** could be integrated:
- Known malicious IP addresses (C2 servers)
- File hashes (malware samples)
- Domain names (phishing sites)

**Implementation**:
1. Maintain IOC database (separate SQLite table or external API)
2. Cross-reference network events against IP blocklists
3. Alert on matches

**Example**:
```sql
-- Check if remote IP is in blocklist
SELECT ne.*, bl.description
FROM network_events ne
JOIN ip_blocklist bl ON ne.remote_addr = bl.ip_address
WHERE ne.timestamp >= datetime('now', '-1 hour');
```

---

## Conclusion

The EDR Agent provides valuable defensive monitoring capabilities but should be considered **one layer in a defense-in-depth strategy**. It is most effective when combined with:

- Endpoint protection platforms (antivirus, EDR)
- Network security monitoring (IDS/IPS, NTA)
- Security Information and Event Management (SIEM)
- User awareness training
- Vulnerability management
- Incident response procedures

**Key Principle**: This tool is for **authorized defensive security monitoring only**. Misuse for offensive purposes or unauthorized monitoring is strictly prohibited and may be illegal.

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Controls: https://www.cisecurity.org/controls/
- Windows Security Best Practices: https://docs.microsoft.com/en-us/windows/security/
- Rust Security Guidelines: https://anssi-fr.github.io/rust-guide/
