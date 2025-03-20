use eframe::egui;
use regex::Regex;
use rfd::FileDialog;
use std::collections::{HashMap, HashSet};
use std::fs;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "log_hawk",
        options,
        Box::new(|_cc| Ok(Box::new(LogHawkApp::default()))),
    )
}

#[derive(Default)]
struct LogHawkApp {
    logs: Vec<LogEntry>,
    filtered_logs: Vec<LogEntry>,
    selected_file: Option<String>,
    suspicious_ips: Vec<String>,
    stats: LogStats,
    show_logs: bool,
    filter_ip: String,
    filter_status: String,
}

impl eframe::App for LogHawkApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("log_hawk");

            if ui.button("Выбрать файл").clicked() {
                if let Some(path) = FileDialog::new().add_filter("Text files", &["txt"]).pick_file() {
                    let path_str = path.display().to_string();
                    self.selected_file = Some(path_str.clone());
                    self.logs = read_logs(&path_str);
                    self.stats = analyze_logs(&self.logs);
                    self.suspicious_ips = detect_suspicious_ips(&self.logs);
                    self.apply_filter();
                }
            }

            if let Some(ref file) = self.selected_file {
                ui.label(format!("Выбран файл: {}", file));
            }

            ui.separator();
            ui.heading("Статистика:");
            ui.label(format!("Всего логов: {}", self.stats.total_logs));
            ui.label(format!("Уникальных IP: {}", self.stats.unique_ips.len()));
            ui.label(format!("Успешных входов: {}", self.stats.successful_logins));
            ui.label(format!("Неудачных входов: {}", self.stats.failed_logins));

            ui.separator();
            ui.heading("Подозрительные IP:");
            for ip in &self.suspicious_ips {
                ui.colored_label(egui::Color32::from_rgb(255, 165, 0), ip);
            }

            ui.separator();
            let label = if self.show_logs { "▼ Скрыть логи" } else { "▶ Показать логи" };
            if ui.button(label).clicked() {
                self.show_logs = !self.show_logs;
            }

            if self.show_logs {
                ui.separator();
                ui.heading("Фильтрация логов:");
                ui.horizontal(|ui| {
                    ui.label("Фильтр по IP:");
                    if ui.text_edit_singleline(&mut self.filter_ip).changed() {
                        self.apply_filter();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Фильтр по статусу:");
                    if ui.text_edit_singleline(&mut self.filter_status).changed() {
                        self.apply_filter();
                    }
                });
                
                ui.separator();
                ui.heading("Логи:");
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    for log in &self.filtered_logs {
                        let color = if log.status.contains("False") {
                            egui::Color32::RED
                        } else if log.status.contains("True") {
                            egui::Color32::GREEN
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(color, format!(
                            "[{}] {} | {} | {}",
                            log.timestamp, log.message, log.status, log.ip
                        ));
                    }
                });
            }
        });
    }
}

#[derive(Debug, Clone)]
struct LogEntry {
    timestamp: String,
    status: String,
    message: String,
    ip: String,
}

#[derive(Default)]
struct LogStats {
    total_logs: usize,
    successful_logins: usize,
    failed_logins: usize,
    unique_ips: HashSet<String>,
}

impl LogHawkApp {
    fn apply_filter(&mut self) {
        self.filtered_logs = self.logs.iter()
            .filter(|log| {
                (self.filter_ip.is_empty() || log.ip.contains(&self.filter_ip)) &&
                (self.filter_status.is_empty() || log.status.contains(&self.filter_status))
            })
            .cloned()
            .collect();
    }
}

fn read_logs(filename: &str) -> Vec<LogEntry> {
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

fn analyze_logs(logs: &[LogEntry]) -> LogStats {
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

fn detect_suspicious_ips(logs: &[LogEntry]) -> Vec<String> {
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
