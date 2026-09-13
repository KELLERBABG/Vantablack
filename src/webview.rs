//! The native desktop application — the default build, and the primary way
//! people are meant to use Global Ghost Net.
//!
//! It hosts the control center in a frameless tao window with a system-tray
//! icon, so no browser tab is involved. The page talks back over wry's IPC
//! bridge (`drag` / `hide` / `quit`), and closing the window hides it back to
//! the tray, the way a VPN app normally behaves — it never kills the node.
//! The HTTP control center underneath stays available for headless nodes and
//! for anyone who prefers a browser (`GHOST_NO_GUI=1`).
//!
//! This module deliberately does **not** spawn its own thread: tao refuses to
//! build an `EventLoop` off the main thread on Windows, and macOS requires the
//! main thread. The caller (`main`) owns that thread and runs the node on a
//! separate one.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{Icon, Window, WindowBuilder};
use vantablack::ghost::icon;
use vantablack::ghost::GhostNode;
use wry::WebViewBuilder;

/// Block until the control-center HTTP listener answers. The node starts that
/// listener on its own thread, so the window can otherwise race it.
fn wait_for_control_center(port: u16) -> bool {
    let target = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..30 {
        if std::net::TcpStream::connect_timeout(&target, Duration::from_millis(150)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Last-resort fallback when no window can be created at all: open the control
/// center in the user's normal browser, exactly like a headless build does.
fn open_in_browser(port: u16) {
    let url = format!("http://127.0.0.1:{port}");
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", &url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
}

/// Build the tray icon. Returns the menu items and channel receivers so the
/// event loop can service them. Failure is never fatal — the window is the
/// application, the tray is a convenience.
#[allow(clippy::type_complexity)]
fn build_tray(
    nc: &Option<Arc<GhostNode>>,
) -> Option<(
    tray_icon::menu::MenuItem,
    Option<tray_icon::menu::CheckMenuItem>,
    tray_icon::menu::MenuItem,
)> {
    use tray_icon::menu::{CheckMenuItem, Menu, MenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    // The real application icon, at the size a tray actually asks for. The
    // image is embedded, so there is no icon file to lose track of next to the
    // executable.
    let Some(icon) =
        icon::ui_icon(32).and_then(|i| Icon::from_rgba(i.rgba, i.width, i.height).ok())
    else {
        tracing::warn!("Tray unavailable: the application icon could not be loaded");
        return None;
    };

    let open_item = MenuItem::new("Show Global Ghost Net", true, None);
    let beacon_item = nc.as_ref().map(|node| {
        CheckMenuItem::new(
            "Beacon discovery",
            true,
            node.beacon_enabled.load(Ordering::Relaxed),
            None,
        )
    });
    let quit_item = MenuItem::new("Quit Global Ghost Net", true, None);
    let menu = Menu::new();
    let _ = menu.append(&open_item);
    if let Some(item) = &beacon_item {
        let _ = menu.append(item);
    }
    let _ = menu.append(&quit_item);
    if TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .with_tooltip("Global Ghost Net")
        .build()
        .is_err()
    {
        tracing::warn!("Tray unavailable: no system tray on this desktop");
        return None;
    }
    Some((open_item, beacon_item, quit_item))
}

/// Run the desktop application. Never returns: every exit path goes through
/// `std::process::exit` (tray "Quit", the in-page quit button, or a window
/// that could not be created).
pub fn run_desktop(control_port: u16, nc: Option<Arc<GhostNode>>) -> ! {
    if !wait_for_control_center(control_port) {
        tracing::warn!(
            port = control_port,
            "Control center has not answered yet; opening the window anyway"
        );
    }

    let menu_rx = tray_icon::menu::MenuEvent::receiver();
    let tray_rx = tray_icon::TrayIconEvent::receiver();
    let tray = build_tray(&nc); // The window icon below sets `WM_SETICON`/`ICON_SMALL`, which covers the
                                // title bar and the Alt-Tab entry. The *taskbar button* reads a different
                                // one — `ICON_BIG` — so a second `WM_SETICON` is issued after the window
                                // exists (tao's builder has no equivalent). Without it Windows scales the
                                // small icon up or falls back to the executable's resources.
                                //
                                // A decode failure is not fatal: the window opens without an icon rather
                                // than not opening at all.
    let window_icon =
        icon::ui_icon(64).and_then(|i| Icon::from_rgba(i.rgba, i.width, i.height).ok());

    let event_loop = EventLoopBuilder::new().build();
    // Visible from the start: this is the application, not a tray-only helper.
    // Closing it later hides it back to the tray.
    let window = match WindowBuilder::new()
        .with_title("Global Ghost Net")
        .with_window_icon(window_icon)
        .with_decorations(false)
        .with_inner_size(LogicalSize::new(1180.0, 820.0))
        .with_min_inner_size(LogicalSize::new(720.0, 520.0))
        .with_visible(true)
        .build(&event_loop)
    {
        Ok(window) => window,
        Err(e) => {
            tracing::warn!("Could not create a window ({e}); opening a browser tab instead");
            open_in_browser(control_port);
            std::process::exit(1);
        }
    };
    // Frameless windows need their own drag strip, which is why the page sends
    // us `drag` over IPC. A soft shadow keeps it looking intentional.
    #[cfg(target_os = "windows")]
    {
        use tao::platform::windows::WindowExtWindows;
        window.set_undecorated_shadow(true);
        let taskbar_icon =
            icon::ui_icon(64).and_then(|i| Icon::from_rgba(i.rgba, i.width, i.height).ok());
        window.set_taskbar_icon(taskbar_icon);
    }

    // The IPC handler and the event loop both need the window, and both run on
    // this thread, so a plain Rc<RefCell<..>> is the right tool.
    let slot: Rc<RefCell<Option<Window>>> = Rc::new(RefCell::new(Some(window)));
    let ipc_slot = Rc::clone(&slot);
    let ipc_node = nc.clone();
    let url = format!("http://127.0.0.1:{control_port}/?native=1");

    let built = {
        let borrowed = slot.borrow();
        let Some(win) = borrowed.as_ref() else {
            std::process::exit(1);
        };
        WebViewBuilder::new()
            .with_url(url)
            .with_ipc_handler(move |request: wry::http::Request<String>| {
                match request.body().as_str() {
                    "drag" => {
                        if let Some(win) = ipc_slot.borrow().as_ref() {
                            let _ = win.drag_window();
                        }
                    }
                    "hide" => {
                        if let Some(win) = ipc_slot.borrow().as_ref() {
                            win.set_visible(false);
                        }
                    }
                    "quit" => {
                        tracing::info!("Desktop window: quit requested");
                        if let Some(node) = &ipc_node {
                            node.running.store(false, Ordering::Relaxed);
                        }
                        std::process::exit(0);
                    }
                    other => tracing::debug!("Desktop window: unhandled ipc message '{other}'"),
                }
            })
            .build(win)
    };

    let webview = match built {
        Ok(view) => view,
        Err(e) => {
            tracing::warn!("WebView unavailable ({e}); opening a browser tab instead");
            open_in_browser(control_port);
            std::process::exit(1);
        }
    };

    if let Some(win) = slot.borrow().as_ref() {
        win.set_focus();
    }
    tracing::info!(
        port = control_port,
        "Desktop window open (frameless, tray icon, closes to tray)"
    );

    event_loop.run(move |event, _elwt, control| {
        *control = ControlFlow::Wait;

        while let Ok(ev) = menu_rx.try_recv() {
            match &tray {
                Some((open_item, beacon_item, quit_item)) => {
                    if ev.id == open_item.id() {
                        if let Some(win) = slot.borrow().as_ref() {
                            win.set_visible(true);
                            win.set_focus();
                            let _ = webview.set_visible(true);
                        }
                    } else if beacon_item.as_ref().is_some_and(|item| ev.id == item.id()) {
                        if let Some(node) = &nc {
                            let on = !node.beacon_enabled.load(Ordering::Relaxed);
                            node.beacon_enabled.store(on, Ordering::Relaxed);
                            tracing::info!(
                                "Tray: beacon discovery {}",
                                if on { "ON" } else { "OFF" }
                            );
                        }
                    } else if ev.id == quit_item.id() {
                        tracing::info!("Tray: quit requested");
                        if let Some(node) = &nc {
                            node.running.store(false, Ordering::Relaxed);
                        }
                        std::process::exit(0);
                    }
                }
                None => break,
            }
        }
        let _ = tray_rx.try_recv(); // keep the channel drained

        // tao only *reports* WM_CLOSE (it does not destroy the window), so
        // ignoring the destroy is exactly how "minimize to tray" is done.
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            // "Close" means "get out of my way", not "stop my VPN".
            if let Some(win) = slot.borrow().as_ref() {
                win.set_visible(false);
            }
            let _ = webview.set_visible(false);
            tracing::info!("Window hidden to tray (node keeps running)");
        }
    });
}
