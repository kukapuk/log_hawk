use eframe::egui;
mod log_analyzer;
mod tab;
use tab::Tab;
mod log_hawk_app;
use log_hawk_app::*;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "LogHawk",
        options,
        Box::new(|_cc| Ok(Box::new(LogHawkApp::default()))),
    )
}

impl eframe::App for LogHawkApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("side_panel").show(ctx, |ui| {
            ui.heading("📊 LogHawk");
            ui.separator();
            
            if ui.selectable_label(self.current_tab == Tab::Logs, "📜 Логи").clicked() {
                self.current_tab = Tab::Logs;
            }
            if ui.selectable_label(self.current_tab == Tab::Statistics, "📈 Статистика").clicked() {
                self.current_tab = Tab::Statistics;
            }
            if ui.selectable_label(self.current_tab == Tab::SuspiciousIPs, "🔍 Подозрительные IP").clicked() {
                self.current_tab = Tab::SuspiciousIPs;
            }
            if ui.selectable_label(self.current_tab == Tab::Graphics, "📊 Графики").clicked() {
                self.current_tab = Tab::Graphics;
            }
            if ui.selectable_label(self.current_tab == Tab::IpChart, "📊 Часто встречаемые IP").clicked() {
                self.current_tab = Tab::IpChart;
            }
            if ui.selectable_label(self.current_tab == Tab::IndividualAttemptsGraph, "📊 Индивидуальные попытки IP").clicked() {
                self.current_tab = Tab::IndividualAttemptsGraph;
            }
            if ui.selectable_label(self.current_tab == Tab::Settings, "⚙ Настройки").clicked() {
                self.current_tab = Tab::Settings;
            }
        });
        
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                Tab::Logs => self.show_logs_tab(ui),
                Tab::Statistics => self.show_statistics_tab(ui),
                Tab::SuspiciousIPs => self.show_suspicious_ips_tab(ui),
                Tab::Settings => {
                    ui.label("⚙ Settings here");
                },
                Tab::Graphics => {
                    self.show_graphs_tab(ui);
                },
                Tab::IpChart => {
                    self.show_ip_pie_chart(ui);
                },
                Tab::IndividualAttemptsGraph => {
                    self.show_individual_attempts_graph(ui);
                },
            }
        });
    }
}
