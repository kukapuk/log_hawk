use eframe::egui;
use regex::Regex;
use rfd::FileDialog;
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
    selected_file: Option<String>,
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
                }
            }

            if let Some(ref file) = self.selected_file {
                ui.label(format!("Выбран файл: {}", file));
            }

            ui.separator();

            for log in &self.logs {
                ui.label(format!(
                    "[{}] {} | {} | {}",
                    log.timestamp, log.message, log.status, log.ip
                ));
            }
        });
    }
}

#[derive(Debug)]
struct LogEntry {
    timestamp: String,
    status: String,
    message: String,
    ip: String,
}


fn read_logs(filename: &str) -> Vec<LogEntry> {
    let mut entries = Vec::new();
    if let Ok(contents) = fs::read_to_string(filename) {
        let re_http = Regex::new(r"\[(\d{2}:\d{2}:\d{2}) INF\] (HTTP \w+ [^ ]+) responded (\d+)").unwrap();
        let re_auth = Regex::new(r"\[(\d{2}:\d{2}:\d{2}) INF\] User:(\w+) Status:(\w+) Messages:(.*?) ActionName:\w+ ClientIp:(\d+\.\d+\.\d+\.\d+)").unwrap();

        for line in contents.lines() {
            if let Some(caps) = re_http.captures(line) {
                entries.push(LogEntry {
                    timestamp: caps[1].to_string(),
                    status: caps[3].to_string(),
                    message: caps[2].to_string(),
                    ip: "N/A".to_string(),
                });
            } else if let Some(caps) = re_auth.captures(line) {
                entries.push(LogEntry {
                    timestamp: caps[1].to_string(),
                    status: format!("Status:{}", &caps[3].to_string()),
                    message: format!("User:{} - Messages:{}", &caps[2].to_string(), &caps[4].to_string()),
                    ip: caps[5].to_string(),
                });
            }
        }
    } else {
        println!("error when read file!");
    }
    entries
}

