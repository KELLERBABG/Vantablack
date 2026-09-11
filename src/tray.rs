//! Optional system-tray UI — compiled only with the `tray` cargo feature
//! (`cargo build --features tray`). Runs on its own thread with a tao event
//! loop; menu clicks toggle node state directly.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use vantablack::ghost::GhostNode;

pub fn run_tray(nc: Arc<GhostNode>) {
    std::thread::spawn(move || {
        use tray_icon::menu::{CheckMenuItem, Menu, MenuItem};
        use tray_icon::{Icon, TrayIconBuilder};

        // Simple 32x32 RGBA icon (filled disc) — no image asset needed.
        let mut rgba = vec![0u8; 32 * 32 * 4];
        for y in 0..32 {
            for x in 0..32 {
                let dx = x as f32 - 15.5;
                let dy = y as f32 - 15.5;
                if dx * dx + dy * dy <= 13.5 * 13.5 {
                    let i = (y * 32 + x) * 4;
                    rgba[i] = 24;
                    rgba[i + 1] = 200;
                    rgba[i + 2] = 120;
                    rgba[i + 3] = 255;
                }
            }
        }
        let Ok(icon) = Icon::from_rgba(rgba, 32, 32) else { return; };

        let beacon_item = CheckMenuItem::new("Beacon discovery", true, true, None);
        let quit_item = MenuItem::new("Quit", true, None);
        let menu = Menu::new();
        let _ = menu.append(&beacon_item);
        let _ = menu.append(&quit_item);
        if TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .with_tooltip("Vantablack Mesh")
            .build()
            .is_err()
        {
            return;
        }

        let menu_rx = tray_icon::menu::MenuEvent::receiver();
        let tray_rx = tray_icon::TrayIconEvent::receiver();
        let evt_loop: tao::event_loop::EventLoop<()> =
            tao::event_loop::EventLoopBuilder::new().build();

        evt_loop.run(move |_event, _el, control| {
            use tao::event_loop::ControlFlow;
            *control = ControlFlow::Poll;
            while let Ok(ev) = menu_rx.try_recv() {
                if ev.id == beacon_item.id() {
                    let on = !nc.beacon_enabled.load(Ordering::Relaxed);
                    nc.beacon_enabled.store(on, Ordering::Relaxed);
                    tracing::info!("Tray: beacon discovery {}", if on { "ON" } else { "OFF" });
                } else if ev.id == quit_item.id() {
                    tracing::info!("Tray: quit requested");
                    nc.running.store(false, Ordering::Relaxed);
                    std::process::exit(0);
                }
            }
            let _ = tray_rx.try_recv(); // keep the channel drained
        });
    });
}
