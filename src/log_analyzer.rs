use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;


#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub status: String,
    pub message: String,
    pub ip: String,
}

#[derive(Default)]
pub struct LogStats {
    pub total_logs: usize,
    pub successful_logins: usize,
    pub failed_logins: usize,
    pub unique_ips: HashSet<String>,
}

pub fn read_logs(filename: &str) -> Vec<LogEntry> {
    let mut entries = Vec::new();
    if let Ok(contents) = fs::read_to_string(filename) {
        let re_auth = Regex::new(r"\[(\d{2}:\d{2}:\d{2}) INF\] User:(\w+) Status:(\w+) Messages:(.*?) ActionName:\w+ ClientIp:(\d+\.\d+\.\d+\.\d+)").unwrap();

        for line in contents.lines() {
            if let Some(caps) = re_auth.captures(line) {
                entries.push(LogEntry {
                    timestamp: caps[1].to_string(),
                    status: format!("Status:{}", &caps[3]),
                    message: format!("User:{} - Messages:{}", &caps[2], &caps[4]),
                    ip: caps[5].to_string(),
                });
            }
        }
    }
    entries
}

pub fn analyze_logs(logs: &[LogEntry]) -> LogStats {
    let mut stats = LogStats::default();

    for log in logs {
        stats.total_logs += 1;
        if log.status.contains("False") {
            stats.failed_logins += 1;
        } else if log.status.contains("True") {
            stats.successful_logins += 1;
        }
        if log.ip != "N/A" {
            stats.unique_ips.insert(log.ip.clone());
        }
    }

    stats
}

pub fn detect_suspicious_ips(logs: &[LogEntry]) -> Vec<String> {
    let mut failed_attempts: HashMap<String, usize> = HashMap::new();

    for log in logs {
        if log.status.contains("False") {
            *failed_attempts.entry(log.ip.clone()).or_insert(0) += 1;
        }
    }

    failed_attempts
        .into_iter()
        .filter(|&(_, count)| count > 3)
        .map(|(ip, _)| ip)
        .collect()
}
