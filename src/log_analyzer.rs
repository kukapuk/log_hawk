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

pub fn calculate_risk_scores(logs: &[LogEntry]) -> Vec<(String, f64)> {
    use std::collections::HashMap;

    let mut ip_entries: HashMap<String, Vec<&LogEntry>> = HashMap::new();
    for log in logs {
        ip_entries.entry(log.ip.clone()).or_default().push(log);
    }
    
    let mut raw_scores = vec![];
    let mut total_counts = vec![];

    for (ip, entries) in &ip_entries {
        let total = entries.len() as f64;
        let failed = entries.iter().filter(|l| l.status.contains("False")).count() as f64;
        total_counts.push(total);
        raw_scores.push((ip.clone(), total, failed));
    }

    let min_total = total_counts.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_total = total_counts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let alpha = 0.7;
    let beta = 0.3;
    
    let mut results = vec![];

    for (ip, total, failed) in raw_scores {
        let failed_ratio = if total > 0.0 { failed / total } else { 0.0 };
        let norm_activity = if (max_total - min_total).abs() < 1e-6 {
            0.0
        } else {
            (total - min_total) / (max_total - min_total)
        };

        let risk_score = (alpha * failed_ratio + beta * norm_activity).min(1.0);
        results.push((ip, risk_score));
    }

    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

pub fn risk_to_color(score: f64) -> egui::Color32 {
    let clamped = score.clamp(0.0, 1.0);
    let r = (clamped * 255.0) as u8;
    let g = ((1.0 - clamped) * 255.0) as u8;
    egui::Color32::from_rgb(r, g, 0)
}

