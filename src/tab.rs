
#[derive(Default, PartialEq)]
pub enum Tab {
    #[default]
    Logs,
    Statistics,
    SuspiciousIPs,
    Settings,
    Graphics,
    IpChart,
    IndividualAttemptsGraph,
    RiskAnalysis,
}
