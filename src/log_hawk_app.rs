use egui::Color32;
use egui::Stroke;
use rfd::FileDialog;
use crate::log_analyzer::*;
use crate::tab::*;
use egui_plot::*;
use std::collections::BTreeMap;

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
        });
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
                ui.label("🔍 Подозрительные IP-адреса");
                
                let suspicious_counts: Vec<Bar> = self.suspicious_ips.iter().enumerate().map(|(i, ip)| {
                    Bar::new(i as f64, 1.0)
                        .fill(egui::Color32::DARK_RED)
                        .name(ip)
                }).collect();
                
                if !suspicious_counts.is_empty() {
                    Plot::new("suspicious_ips").view_aspect(2.0).show(ui, |plot_ui| {
                        plot_ui.bar_chart(BarChart::new(suspicious_counts));
                    });
                } else {
                    ui.label("Нет подозрительных IP");
                }
            });            

            ui.vertical(|ui| {
                ui.label("⏳ Активность логов по времени");
    
                let mut total_counts: BTreeMap<String, i32> = BTreeMap::new();
                let mut success_counts: BTreeMap<String, i32> = BTreeMap::new();
                let mut failed_counts: BTreeMap<String, i32> = BTreeMap::new();
    
                for log in &self.logs {
                    *total_counts.entry(log.timestamp.clone()).or_insert(0) += 1;
    
                    if log.status.contains("True") {
                        *success_counts.entry(log.timestamp.clone()).or_insert(0) += 1;
                    } else if log.status.contains("False") {
                        *failed_counts.entry(log.timestamp.clone()).or_insert(0) += 1;
                    }
                }
    
                let time_labels: Vec<_> = total_counts.keys().cloned().collect();
    
                let make_line_points = |counts: &BTreeMap<String, i32>| -> Vec<[f64; 2]> {
                    counts.iter()
                        .enumerate()
                        .map(|(i, (_, count))| [i as f64, *count as f64])
                        .collect()
                };
    
                let total_points = make_line_points(&total_counts);
                let success_points = make_line_points(&success_counts);
                let failed_points = make_line_points(&failed_counts);
    
                Plot::new("log_activity")
                    .view_aspect(2.0)
                    .legend(Legend::default())
                    .show(ui, |plot_ui| {
                        plot_ui.line(Line::new(PlotPoints::from(total_points.clone()))
                            .name("Общая активность")
                            .color(egui::Color32::WHITE));
    
                        plot_ui.line(Line::new(PlotPoints::from(success_points.clone()))
                            .name("Успешные входы")
                            .color(egui::Color32::GREEN));
    
                        plot_ui.line(Line::new(PlotPoints::from(failed_points.clone()))
                            .name("Неудачные входы")
                            .color(egui::Color32::RED));
    
                        for (i, label) in time_labels.iter().enumerate() {
                            plot_ui.text(Text::new([i as f64, 0.0].into(), label.clone()));
                        }
                    });
            });
            
            
            ui.vertical(|ui| {
                ui.label("⚠️ Ошибки по категориям");
            
                let other_errors = self.stats.total_logs - self.stats.successful_logins - self.stats.failed_logins;
            
                let error_types = [("Auth Fail", self.stats.failed_logins), ("Other Errors", other_errors)];
            
                let bars: Vec<Bar> = error_types.iter().enumerate().map(|(i, (label, count))| {
                    Bar::new(i as f64, *count as f64).name(label).fill(egui::Color32::RED)
                }).collect();
            
                Plot::new("error_types")
                    .view_aspect(1.5)
                    .show(ui, |plot_ui| {
                        plot_ui.bar_chart(BarChart::new(bars));
                    });
            });            
        });
    }

    pub fn show_ip_pie_chart(&self, ui: &mut egui::Ui) {
        use std::f64::consts::PI;
    
        ui.label("🌍 Распределение логов по IP-адресам");
    
        let mut ip_counts = BTreeMap::new();
        for log in &self.logs {
            *ip_counts.entry(log.ip.clone()).or_insert(0) += 1;
        }
    
        if ip_counts.is_empty() {
            ui.label("Нет данных для отображения.");
            return;
        }
    
        let total_logs: i32 = ip_counts.values().sum();

        let colors = [
            Color32::from_rgb(255, 99, 132),
            Color32::from_rgb(54, 162, 235),
            Color32::from_rgb(255, 206, 86),
            Color32::from_rgb(75, 192, 192),
            Color32::from_rgb(153, 102, 255),
            Color32::from_rgb(255, 159, 64),
        ];

        let center = [0.0, 0.0];
        let radius = 1.0;
        let mut start_angle = 0.0;
        let mut color_index = 0;
        let legend: Vec<(String, Color32)> = vec![];

        Plot::new("ip_pie_chart")
            .view_aspect(1.0)
            .legend(Legend::default().position(Corner::LeftTop))
            .show(ui, |plot_ui| {
                for (ip, count) in ip_counts {
                    let fraction = count as f64 / total_logs as f64;
                    let sweep_angle = fraction * 2.0 * PI;
                    let end_angle = start_angle + sweep_angle;

                    let color = colors[color_index % colors.len()];
                    color_index += 1;

                    let mut points = vec![center];
                    for i in 0..=30 {
                        let angle = start_angle + (i as f64 / 30.0) * sweep_angle;
                        points.push([
                            center[0] + radius * angle.cos(),
                            center[1] + radius * angle.sin(),
                        ]);
                    }
                    points.push(center);

                    plot_ui.polygon(
                        Polygon::new(PlotPoints::from(points))
                            .stroke(Stroke::new(10.0, color)),
                    );

                    let label_angle = start_angle + sweep_angle / 2.0;
                    let label_pos = PlotPoint::new(
                        center[0] + 1.3 * radius * label_angle.cos(),
                        center[1] + 1.3 * radius * label_angle.sin(),
                    );

                    let percentage = (fraction * 100.0) as u8;
                    plot_ui.text(Text::new(
                        label_pos,
                        format!("{}% ({})", percentage, ip),
                    )
                    .color(Color32::WHITE));

                    start_angle = end_angle;
                }
            });

        ui.separator();
        for (ip, color) in legend {
            ui.horizontal(|ui| {
                let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(10.0, 10.0));
                ui.painter().rect_filled(rect, 0.0, color);
                ui.label(ip);
            });
        }
    }

    pub fn show_individual_attempts_graph(&self, ui: &mut egui::Ui) {
        let ip_attempts: Vec<(String, usize, usize)> = vec![
            ("192.168.1.1".to_string(), 10, 5),
            ("192.168.1.2".to_string(), 8, 3),
            ("10.0.0.1".to_string(), 6, 7),
        ];

        Plot::new("ip_attempts_chart")
            .view_aspect(2.0)
            .legend(egui_plot::Legend::default().position(Corner::LeftTop))
            .show(ui, |plot_ui| {
                let mut bars_success = vec![];
                let mut bars_failed = vec![];

                for (i, (_, success, failed)) in ip_attempts.iter().enumerate() {
                    let x = i as f64;
                    bars_success.push(Bar::new(x, *success as f64).fill(Color32::BLUE));
                    bars_failed.push(Bar::new(x, *failed as f64).fill(Color32::RED));
                }

                plot_ui.bar_chart(BarChart::new(bars_success).name("Успешные попытки"));
                plot_ui.bar_chart(BarChart::new(bars_failed).name("Неудачные попытки"));
            });
    }
}
