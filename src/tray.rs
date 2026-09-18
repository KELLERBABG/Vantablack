//! Optional system-tray UI — compiled only with the `tray` cargo feature
//! (`cargo build --features tray`). Runs on its own thread with a tao event
//! loop; menu clicks toggle node state directly.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use vantablack::ghost::icon;
use vantablack::ghost::GhostNode;

pub fn run_tray(nc: Arc<GhostNode>) {
    std::thread::spawn(move || {
        use tray_icon::menu::{CheckMenuItem, Menu, MenuItem};
        use tray_icon::{Icon, TrayIconBuilder};

        // The real application icon, embedded in the binary.
        let Some(icon) =
            icon::ui_icon(32).and_then(|i| Icon::from_rgba(i.rgba, i.width, i.height).ok())
        else {
            return;
        };

        let open_item = MenuItem::new("Open Web Control Center", true, None);
        let beacon_item = CheckMenuItem::new("Beacon discovery", true, true, None);
        let quit_item = MenuItem::new("Quit Vantablack", true, None);
        let menu = Menu::new();
        let _ = menu.append(&open_item);
        let _ = menu.append(&beacon_item);
        let _ = menu.append(&quit_item);
        if TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .with_tooltip("Vantablack")
            .build()
            .is_err()
        {
            return;
        }

        let menu_rx = tray_icon::menu::MenuEvent::receiver();
        let tray_rx = tray_icon::TrayIconEvent::receiver();
        // This loop lives on a spawned thread, which tao rejects on Windows
        // unless we opt in explicitly. Without this the tray build panicked at
        // startup and never showed an icon.
        let mut builder = tao::event_loop::EventLoopBuilder::new();
        #[cfg(target_os = "windows")]
        {
            use tao::platform::windows::EventLoopBuilderExtWindows;
            builder.with_any_thread(true);
        }
        let evt_loop: tao::event_loop::EventLoop<()> = builder.build();

        evt_loop.run(move |_event, _el, control| {
            use tao::event_loop::ControlFlow;
            *control = ControlFlow::Poll;
            while let Ok(ev) = menu_rx.try_recv() {
                if ev.id == open_item.id() {
                    let url = "http://127.0.0.1:2270";
                    #[cfg(target_os = "windows")]
                    let _ = std::process::Command::new("cmd")
                        .args(["/C", "start", url])
                        .spawn();
                    #[cfg(target_os = "macos")]
                    let _ = std::process::Command::new("open").arg(url).spawn();
                    #[cfg(target_os = "linux")]
                    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
                } else if ev.id == beacon_item.id() {
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
