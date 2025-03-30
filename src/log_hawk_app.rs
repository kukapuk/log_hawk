use rfd::FileDialog;
use crate::log_analyzer::*;
use crate::tab::*;
use egui_plot::*;
use egui::Color32;


#[derive(Default)]
pub struct LogHawkApp {
    pub logs: Vec<LogEntry>,
    pub filtered_logs: Vec<LogEntry>,
    pub selected_file: Option<String>,
    pub suspicious_ips: Vec<String>,
    pub stats: LogStats,
    pub filter_ip: String,
    pub filter_status: String,
    pub current_tab: Tab,
}

impl LogHawkApp {
    pub fn show_logs_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📜 Анализ логов");
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
        ui.label("🔍 Фильтрация логов:");
        ui.horizontal(|ui| {
            ui.label("🔹 IP:");
            if ui.text_edit_singleline(&mut self.filter_ip).changed() {
                self.apply_filter();
            }
            ui.label("🔹 Статус:");
            if ui.text_edit_singleline(&mut self.filter_status).changed() {
                self.apply_filter();
            }
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
    
    pub fn show_statistics_tab(&self, ui: &mut egui::Ui) {
        ui.heading("📈 Статистика");
        ui.separator();
        ui.label(format!("Всего логов: {}", self.stats.total_logs));
        ui.label(format!("Уникальных IP: {}", self.stats.unique_ips.len()));
        ui.label(format!("✅ Успешные входы: {}", self.stats.successful_logins));
        ui.label(format!("❌ Неудачные входы: {}", self.stats.failed_logins));
    }
    
    pub fn show_suspicious_ips_tab(&self, ui: &mut egui::Ui) {
        ui.heading("🔍 Подозрительные IP");
        ui.separator();
        for ip in &self.suspicious_ips {
            ui.colored_label(egui::Color32::from_rgb(255, 69, 0), ip);
        }
    }
    
    pub fn apply_filter(&mut self) {
        self.filtered_logs = self.logs.iter()
            .filter(|log| {
                (self.filter_ip.is_empty() || log.ip.contains(&self.filter_ip)) &&
                (self.filter_status.is_empty() || log.status.to_lowercase().contains(&self.filter_status.to_lowercase()))
            })
            .cloned()
            .collect();
    }

    pub fn show_graphs_tab(&self, ui: &mut egui::Ui) {
        ui.heading("📊 Графики");
        ui.separator();
    
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label("✅ Успешные vs ❌ Неудачные входы");
                Plot::new("login_attempts").view_aspect(2.0).show(ui, |plot_ui| {
                    let values = vec![
                        Bar::new(0.0, self.stats.successful_logins as f64).fill(egui::Color32::GREEN),
                        Bar::new(1.0, self.stats.failed_logins as f64).fill(egui::Color32::RED),
                    ];
                    plot_ui.bar_chart(BarChart::new(values));
                });
            });
            ui.separator();
    
            ui.vertical(|ui| {
                ui.label("📊 Активность IP-адресов");
                let mut ip_counts = std::collections::HashMap::new();
                for log in &self.logs {
                    *ip_counts.entry(log.ip.clone()).or_insert(0) += 1;
                }
                let mut bars: Vec<Bar> = ip_counts.iter().enumerate().map(|(i, (ip, count))| {
                    Bar::new(i as f64, *count as f64).fill(egui::Color32::BLUE)
                }).collect();
                if bars.len() > 10 {
                    bars.truncate(10);
                }
                
                Plot::new("ip_activity").view_aspect(2.0).show(ui, |plot_ui| {
                    plot_ui.bar_chart(BarChart::new(bars));
                });
            });
            ui.separator();
    
            ui.vertical(|ui| {
                ui.label("🔍 Подозрительные IP-адреса");
                let suspicious_counts: Vec<Bar> = self.suspicious_ips.iter().enumerate().map(|(i, ip)| {
                    Bar::new(i as f64, 1.0).fill(egui::Color32::DARK_RED)
                }).collect();
                
                if !suspicious_counts.is_empty() {
                    Plot::new("suspicious_ips").view_aspect(2.0).show(ui, |plot_ui| {
                        plot_ui.bar_chart(BarChart::new(suspicious_counts));
                    });
                } else {
                    ui.label("Нет подозрительных IP");
                }
            });
        });
    }    
}
