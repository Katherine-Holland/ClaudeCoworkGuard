// CoworkGuard — macOS Menubar App
// © 2026 Katherine Holland. MIT + Commons Clause.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::Mutex;
use std::path::PathBuf;
use tauri::{
    AppHandle, Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
};

struct AppState {
    proxy_process:  Mutex<Option<Child>>,
    server_process: Mutex<Option<Child>>,
    is_running:     Mutex<bool>,
}

fn find_mitmproxy() -> String {
    let candidates = [
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/mitmproxy",
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/mitmproxy",
        "/usr/local/bin/mitmproxy",
        "/opt/homebrew/bin/mitmproxy",
    ];
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    // Fall back to PATH lookup
    "mitmproxy".to_string()
}

fn find_python() -> String {
    let candidates = [
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/bin/python3",
    ];
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    "python3".to_string()
}

fn get_network_service() -> String {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if !line.starts_with('*') &&
               (line.contains("Wi-Fi") || line.contains("Ethernet") || line.contains("USB")) {
                return line.trim().to_string();
            }
        }
    }
    "Wi-Fi".to_string()
}

fn enable_proxy() {
    let svc = get_network_service();
    let _ = Command::new("networksetup").args(["-setwebproxy", &svc, "127.0.0.1", "8080"]).output();
    let _ = Command::new("networksetup").args(["-setsecurewebproxy", &svc, "127.0.0.1", "8080"]).output();
    let _ = Command::new("networksetup").args(["-setwebproxystate", &svc, "on"]).output();
    let _ = Command::new("networksetup").args(["-setsecurewebproxystate", &svc, "on"]).output();
}

fn disable_proxy() {
    let svc = get_network_service();
    let _ = Command::new("networksetup").args(["-setwebproxystate", &svc, "off"]).output();
    let _ = Command::new("networksetup").args(["-setsecurewebproxystate", &svc, "off"]).output();
}

fn find_install_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("ClaudeCoworkGuard")
}

fn start_coworkguard(app: &AppHandle) {
    let state = app.state::<AppState>();
    let dir = find_install_dir();
    let mitmproxy_bin = find_mitmproxy();
    let python_bin = find_python();

    eprintln!("[CoworkGuard] Using mitmproxy: {}", mitmproxy_bin);
    eprintln!("[CoworkGuard] Using python3: {}", python_bin);
    eprintln!("[CoworkGuard] Install dir: {:?}", dir);

    let proxy = Command::new(&mitmproxy_bin)
        .args(["-s", "proxy.py", "--listen-port", "8080", "--quiet"])
        .current_dir(&dir)
        .spawn();

    match proxy {
        Ok(child) => {
            eprintln!("[CoworkGuard] mitmproxy started");
            *state.proxy_process.lock().unwrap() = Some(child);
        }
        Err(e) => {
            eprintln!("[CoworkGuard] mitmproxy failed: {}", e);
            return;
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(2));

    let server = Command::new(&python_bin)
        .args(["server.py"])
        .current_dir(&dir)
        .spawn();

    match server {
        Ok(child) => {
            eprintln!("[CoworkGuard] server.py started");
            *state.server_process.lock().unwrap() = Some(child);
        }
        Err(e) => eprintln!("[CoworkGuard] server.py failed: {}", e),
    }

    enable_proxy();
    *state.is_running.lock().unwrap() = true;
    let _ = rebuild_menu(app, true);
}

fn stop_coworkguard(app: &AppHandle) {
    let state = app.state::<AppState>();
    disable_proxy();
    if let Some(mut c) = state.proxy_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.server_process.lock().unwrap().take() { let _ = c.kill(); }
    let _ = Command::new("pkill").args(["-f", "mitmproxy"]).output();
    let _ = Command::new("pkill").args(["-f", "server.py"]).output();
    *state.is_running.lock().unwrap() = false;
    let _ = rebuild_menu(app, false);
    eprintln!("[CoworkGuard] Stopped");
}

fn build_menu(app: &AppHandle, running: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let toggle_label = if running { "Stop Protection" } else { "Start Protection" };
    let status_label = if running { "● PROTECTION ON" } else { "○ Protection off" };

    let menu    = Menu::new(app)?;
    let status  = MenuItem::new(app, status_label, false, None::<&str>)?;
    let sep1    = PredefinedMenuItem::separator(app)?;
    let toggle  = MenuItem::with_id(app, "toggle",    toggle_label,        true, None::<&str>)?;
    let dash    = MenuItem::with_id(app, "dashboard", "Open Dashboard →",  true, None::<&str>)?;
    let sep2    = PredefinedMenuItem::separator(app)?;
    let about   = MenuItem::with_id(app, "about",     "About CoworkGuard", true, None::<&str>)?;
    let quit    = MenuItem::with_id(app, "quit",      "Quit",              true, None::<&str>)?;

    menu.append(&status)?;
    menu.append(&sep1)?;
    menu.append(&toggle)?;
    menu.append(&dash)?;
    menu.append(&sep2)?;
    menu.append(&about)?;
    menu.append(&quit)?;
    Ok(menu)
}

fn rebuild_menu(app: &AppHandle, running: bool) -> tauri::Result<()> {
    if let Some(tray) = app.tray_by_id("main") {
        let menu = build_menu(app, running)?;
        tray.set_menu(Some(menu))?;
        tray.set_tooltip(Some(if running {
            "CoworkGuard — Protection ON"
        } else {
            "CoworkGuard — Click to start"
        }))?;
    }
    Ok(())
}

fn check_startup(_app: &AppHandle) {
    let svc = get_network_service();
    let out = Command::new("networksetup").args(["-getwebproxy", &svc]).output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        if text.contains("Enabled: Yes") && text.contains("127.0.0.1") {
            if std::net::TcpStream::connect("127.0.0.1:8080").is_err() {
                disable_proxy();
                eprintln!("[CoworkGuard] Fixed broken proxy state on startup");
            }
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState {
            proxy_process:  Mutex::new(None),
            server_process: Mutex::new(None),
            is_running:     Mutex::new(false),
        })
        .setup(|app| {
            // Hide from Dock — menubar only
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let menu = build_menu(app.handle(), false)?;

            let icon = tauri::image::Image::from_bytes(
                include_bytes!("../icons/tray-icon.png")
            )?;

            TrayIconBuilder::with_id("main")
                .icon(icon)
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| {
                    match event.id().as_ref() {
                        "toggle" => {
                            let running = *app.state::<AppState>().is_running.lock().unwrap();
                            if running { stop_coworkguard(app); } else { start_coworkguard(app); }
                        }
                        "dashboard" => {
                            let _ = open::that("http://localhost:7070");
                        }
                        "about" => {
                            let _ = open::that("https://katherine-holland.github.io/ClaudeCoworkGuard");
                        }
                        "quit" => {
                            stop_coworkguard(app);
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            // Check for broken proxy state on startup
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(3));
                check_startup(&handle);
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running CoworkGuard");
}
