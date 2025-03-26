use eframe::egui;
use rfd::FileDialog;
mod log_analyzer;
use log_analyzer::*;


fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "LogHawk",
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
            ui.heading("📊 LogHawk - Анализ логов");
            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("📂 Выбрать файл").clicked() {
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
                    ui.label(format!("📁 Файл: {}", file));
                }
            });
            
            ui.separator();
            ui.collapsing("📈 Статистика", |ui| {
                ui.label(format!("Всего логов: {}", self.stats.total_logs));
                ui.label(format!("Уникальных IP: {}", self.stats.unique_ips.len()));
                ui.label(format!("✅ Успешные входы: {}", self.stats.successful_logins));
                ui.label(format!("❌ Неудачные входы: {}", self.stats.failed_logins));
            });

            ui.separator();
            ui.collapsing("🔍 Подозрительные IP", |ui| {
                for ip in &self.suspicious_ips {
                    ui.colored_label(egui::Color32::from_rgb(255, 69, 0), ip);
                }
            });
            
            ui.separator();
            if ui.button(if self.show_logs { "▼ Скрыть логи" } else { "▶ Показать логи" }).clicked() {
                self.show_logs = !self.show_logs;
            }
            
            if self.show_logs {
                ui.separator();
                ui.label("🔍 Фильтрация логов:");
                ui.horizontal(|ui| {
                    ui.label("🔹 IP:");
                    if ui.text_edit_singleline(&mut self.filter_ip).changed() {
                        self.apply_filter();
                    };
                    ui.label("🔹 Статус:");
                    if ui.text_edit_singleline(&mut self.filter_status).changed() {
                        self.apply_filter();
                    };
                });
                
                ui.separator();
                ui.label("📜 Логи:");
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    for log in &self.filtered_logs {
                        let color = match log.status.as_str() {
                            s if s.contains("False") => egui::Color32::RED,
                            s if s.contains("True") => egui::Color32::GREEN,
                            _ => egui::Color32::GRAY,
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

impl LogHawkApp {
    fn apply_filter(&mut self) {
        self.filtered_logs = self.logs.iter()
            .filter(|log| {
                (self.filter_ip.is_empty() || log.ip.contains(&self.filter_ip)) &&
                (self.filter_status.is_empty() || log.status.to_lowercase().contains(&self.filter_status.to_lowercase()))
            })
            .cloned()
            .collect();
    }
}
