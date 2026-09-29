//! egui rendering for [`crate::GuiState`].
//!
//! Pure immediate-mode drawing: every function takes `&GuiState` and paints
//! into an `egui::Ui`. No windowing/system dependencies, so the whole view
//! can be render-tested headlessly (see the tests at the bottom) — hosting
//! it in a real window (eframe/egui-winit) is an application-level concern.

use crate::{GuiState, LogLevel};

/// Paint the full dashboard: header, spectrum, peers, store stats, log tail.
pub fn dashboard_ui(ui: &mut egui::Ui, state: &GuiState) {
    ui.heading(state.status_text());
    ui.separator();

    ui.horizontal(|ui| {
        ui.label(format!("Node: {}", short_id(&state.node_id)));
        ui.separator();
        ui.label(format!(
            "RX {:.1} dB / TX {:.1} dB",
            state.rx_gain_db, state.tx_gain_db
        ));
        ui.separator();
        ui.label(format!("MCS: {}", state.mcs));
    });

    ui.add_space(6.0);
    ui.label("Spectrum");
    spectrum_plot(ui, state);

    ui.add_space(6.0);
    ui.label(format!(
        "Peers ({}) — {} pending ACKs, {} bundles stored",
        state.peers.len(),
        state.pending_acks,
        state.stored_bundles
    ));
    peer_table(ui, state);

    ui.add_space(6.0);
    ui.label(format!("Log tail ({} errors)", state.error_count()));
    log_tail(ui, state);
}

/// Bar-chart spectrum with white-space regions tinted.
fn spectrum_plot(ui: &mut egui::Ui, state: &GuiState) {
    let height = 90.0;
    let (rect, _response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, egui::Color32::from_gray(20));

        for &(start, end) in &state.whitespace {
            let n = state.spectrum.len().max(1) as f32;
            let x0 = rect.left() + rect.width() * start as f32 / n;
            let x1 = rect.left() + rect.width() * (end + 1) as f32 / n;
            painter.rect_filled(
                egui::Rect::from_min_max(egui::pos2(x0, rect.top()), egui::pos2(x1, rect.bottom())),
                0.0,
                egui::Color32::from_white_alpha(18),
            );
        }

        if !state.spectrum.is_empty() {
            let n = state.spectrum.len() as f32;
            let bar_w = (rect.width() / n).max(1.0);
            for point in &state.spectrum {
                let x = rect.left() + rect.width() * point.index as f32 / n;
                let h = rect.height() * point.power.clamp(0.0, 1.0) as f32;
                let bar = egui::Rect::from_min_size(
                    egui::pos2(x, rect.bottom() - h),
                    egui::vec2(bar_w.max(1.0), h),
                );
                painter.rect_filled(bar, 0.0, egui::Color32::from_rgb(80, 200, 120));
            }
        }
    }
}

/// Peers table (or a placeholder row when mesh is empty).
fn peer_table(ui: &mut egui::Ui, state: &GuiState) {
    egui::Grid::new("peer_grid")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Peer");
            ui.strong("Alias");
            ui.strong("Last seen");
            ui.strong("Beacons");
            ui.end_row();

            if state.peers.is_empty() {
                ui.label("—");
                ui.label("(no peers discovered)");
                ui.label("—");
                ui.label("—");
                ui.end_row();
            } else {
                for peer in &state.peers {
                    ui.label(short_id(&peer.node_id));
                    ui.label(&peer.alias);
                    ui.label(format!("{}s ago", peer.last_seen_secs));
                    ui.label(peer.beacon_count.to_string());
                    ui.end_row();
                }
            }
        });
}

/// Newest log lines at the bottom, errors tinted red.
fn log_tail(ui: &mut egui::Ui, state: &GuiState) {
    let show = state.log.len().min(12);
    let start = state.log.len() - show;
    for line in &state.log[start..] {
        let color = match line.level {
            LogLevel::Info => egui::Color32::from_gray(180),
            LogLevel::Warn => egui::Color32::from_rgb(230, 200, 80),
            LogLevel::Error => egui::Color32::from_rgb(230, 90, 90),
        };
        ui.colored_label(color, &line.message);
    }
}

/// First 8 bytes of a hex id, shortened for tables.
fn short_id(hex: &str) -> String {
    if hex.len() >= 16 {
        format!("{}…", &hex[..16])
    } else if hex.is_empty() {
        "—".to_string()
    } else {
        hex.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LogLevel, PeerRow};

    /// Render `dashboard_ui` once headlessly and assert it produced
    /// paint primitives without panicking.
    fn render_once(state: &GuiState) -> usize {
        let ctx = egui::Context::default();
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                dashboard_ui(ui, state);
            });
        });
        output.shapes.len()
    }

    #[test]
    fn renders_empty_state_without_panic() {
        let state = GuiState::default();
        assert!(render_once(&state) > 0, "must paint something");
    }

    #[test]
    fn renders_full_state() {
        let mut state = GuiState {
            node_id: "ab".repeat(32),
            running: true,
            center_frequency_hz: 7_100_000,
            sample_rate_sps: 1_000_000.0,
            tx_gain_db: 40.0,
            rx_gain_db: 30.0,
            mcs: "QPSK-1/2".into(),
            pending_acks: 3,
            stored_bundles: 12,
            ..Default::default()
        };
        state.peers.push(PeerRow {
            node_id: "cd".repeat(32),
            alias: "ghost-1".into(),
            last_seen_secs: 5,
            beacon_count: 9,
        });
        state.update_spectrum(
            &(0..128)
                .map(|i| (i as f64).sin().abs() + 0.1)
                .collect::<Vec<_>>(),
        );
        state.log(LogLevel::Info, "boot");
        state.log(LogLevel::Error, "sdr timeout");
        let shapes = render_once(&state);
        assert!(shapes > 0);
        assert_eq!(state.error_count(), 1);
    }

    #[test]
    fn short_id_handles_edge_cases() {
        assert_eq!(short_id(""), "—");
        assert_eq!(short_id("abcd"), "abcd");
        assert_eq!(short_id("0123456789abcdef9999"), "0123456789abcdef…");
    }
}
