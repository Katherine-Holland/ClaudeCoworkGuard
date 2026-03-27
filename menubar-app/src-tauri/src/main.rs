// CoworkGuard — macOS Menubar App
// © 2026 Katherine Holland. MIT + Commons Clause.
//
// Wraps the CoworkGuard proxy stack (mitmproxy + server.py) in a
// native macOS menubar app. No terminal required.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::Mutex;
use std::path::PathBuf;
use tauri::{
    AppHandle, CustomMenuItem, Manager, SystemTray, SystemTrayEvent,
    SystemTrayMenu, SystemTrayMenuItem, SystemTraySubmenu,
};

// ─────────────────────────────────────────────
// App state — tracks running processes
// ─────────────────────────────────────────────

struct AppState {
    proxy_process:  Mutex<Option<Child>>,
    server_process: Mutex<Option<Child>>,
    is_running:     Mutex<bool>,
}

// ─────────────────────────────────────────────
// Find CoworkGuard install directory
// Looks next to the app bundle first, then ~/CoworkGuard
// ─────────────────────────────────────────────

fn find_install_dir() -> PathBuf {
    // Check bundled resources first (production)
    if let Ok(resource_dir) = std::env::current_exe() {
        let bundled = resource_dir
            .parent().unwrap_or(&resource_dir)
            .parent().unwrap_or(&resource_dir)
            .join("Resources");
        if bundled.join("scanner.py").exists() {
            return bundled;
        }
    }
    // Fall back to ~/CoworkGuard (development / manual install)
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("CoworkGuard")
}

// ─────────────────────────────────────────────
// System proxy management
// ─────────────────────────────────────────────

fn get_network_service() -> String {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: vec![],
            stderr: vec![],
        });

    let services = String::from_utf8_lossy(&output.stdout);
    for line in services.lines() {
        if !line.starts_with('*') &&
           (line.contains("Wi-Fi") || line.contains("Ethernet") || line.contains("USB")) {
            return line.trim().to_string();
        }
    }
    "Wi-Fi".to_string()
}

fn enable_proxy() {
    let service = get_network_service();
    let _ = Command::new("networksetup")
        .args(["-setwebproxy", &service, "127.0.0.1", "8080"])
        .output();
    let _ = Command::new("networksetup")
        .args(["-setsecurewebproxy", &service, "127.0.0.1", "8080"])
        .output();
    let _ = Command::new("networksetup")
        .args(["-setwebproxystate", &service, "on"])
        .output();
    let _ = Command::new("networksetup")
        .args(["-setsecurewebproxystate", &service, "on"])
        .output();
}

fn disable_proxy() {
    let service = get_network_service();
    let _ = Command::new("networksetup")
        .args(["-setwebproxystate", &service, "off"])
        .output();
    let _ = Command::new("networksetup")
        .args(["-setsecurewebproxystate", &service, "off"])
        .output();
}

// ─────────────────────────────────────────────
// Start CoworkGuard
// ─────────────────────────────────────────────

fn start_coworkguard(app: &AppHandle) {
    let state = app.state::<AppState>();
    let install_dir = find_install_dir();

    // Start mitmproxy
    let proxy_cmd = Command::new("mitmproxy")
        .args(["-s", "proxy.py", "--listen-port", "8080", "--quiet"])
        .current_dir(&install_dir)
        .spawn();

    match proxy_cmd {
        Ok(child) => {
            *state.proxy_process.lock().unwrap() = Some(child);
        }
        Err(e) => {
            eprintln!("[CoworkGuard] Failed to start mitmproxy: {}", e);
            send_notification(app, "CoworkGuard", "Failed to start proxy — is mitmproxy installed?");
            return;
        }
    }

    // Give mitmproxy a moment to start
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Start dashboard server
    let server_cmd = Command::new("python3")
        .args(["server.py"])
        .current_dir(&install_dir)
        .spawn();

    match server_cmd {
        Ok(child) => {
            *state.server_process.lock().unwrap() = Some(child);
        }
        Err(e) => {
            eprintln!("[CoworkGuard] Failed to start server: {}", e);
        }
    }

    // Enable system proxy
    enable_proxy();

    // Update state
    *state.is_running.lock().unwrap() = true;

    // Update tray menu
    update_tray_menu(app, true);

    send_notification(app, "🛡️ CoworkGuard Active", "Protection is on. All AI traffic is being scanned.");
}

// ─────────────────────────────────────────────
// Stop CoworkGuard
// ─────────────────────────────────────────────

fn stop_coworkguard(app: &AppHandle) {
    let state = app.state::<AppState>();

    // Disable system proxy first — most important step
    disable_proxy();

    // Stop mitmproxy
    if let Some(mut child) = state.proxy_process.lock().unwrap().take() {
        let _ = child.kill();
    }
    // Also kill any stray mitmproxy processes
    let _ = Command::new("pkill").args(["-f", "mitmproxy"]).output();

    // Stop dashboard server
    if let Some(mut child) = state.server_process.lock().unwrap().take() {
        let _ = child.kill();
    }
    let _ = Command::new("pkill").args(["-f", "server.py"]).output();

    // Update state
    *state.is_running.lock().unwrap() = false;

    // Update tray menu
    update_tray_menu(app, false);

    send_notification(app, "CoworkGuard Off", "Protection stopped. Your internet connection is restored.");
}

// ─────────────────────────────────────────────
// Tray menu builder
// ─────────────────────────────────────────────

fn build_tray_menu(is_running: bool) -> SystemTrayMenu {
    let status_text = if is_running {
        "● PROTECTION ON"
    } else {
        "○ Protection off"
    };

    let toggle_text = if is_running {
        "Stop Protection"
    } else {
        "Start Protection"
    };

    let status     = CustomMenuItem::new("status", status_text).disabled();
    let separator1 = SystemTrayMenuItem::Separator;
    let toggle     = CustomMenuItem::new("toggle", toggle_text);
    let dashboard  = CustomMenuItem::new("dashboard", "Open Dashboard →");
    let separator2 = SystemTrayMenuItem::Separator;
    let about      = CustomMenuItem::new("about", "About CoworkGuard");
    let quit       = CustomMenuItem::new("quit", "Quit");

    SystemTrayMenu::new()
        .add_item(status)
        .add_native_item(separator1)
        .add_item(toggle)
        .add_item(dashboard)
        .add_native_item(separator2)
        .add_item(about)
        .add_item(quit)
}

fn update_tray_menu(app: &AppHandle, is_running: bool) {
    let tray = app.tray_handle();
    let _ = tray.set_menu(build_tray_menu(is_running));

    // Update icon — template icons in macOS are automatically
    // inverted for dark/light mode
    let icon_name = if is_running { "tray-active" } else { "tray-icon" };
    if let Ok(icon) = load_tray_icon(icon_name) {
        let _ = tray.set_icon(icon);
    }
}

fn load_tray_icon(name: &str) -> Result<tauri::Icon, Box<dyn std::error::Error>> {
    let path = find_install_dir()
        .parent().unwrap_or(&find_install_dir().clone())
        .join(format!("menubar-app/src-tauri/icons/{}.png", name));
    Ok(tauri::Icon::File(path))
}

// ─────────────────────────────────────────────
// Notifications
// ─────────────────────────────────────────────

fn send_notification(app: &AppHandle, title: &str, body: &str) {
    let _ = tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
        .title(title)
        .body(body)
        .show();
}

// ─────────────────────────────────────────────
// Check for broken proxy state on startup
// (proxy on but mitmproxy not running)
// ─────────────────────────────────────────────

fn check_proxy_state_on_startup(app: &AppHandle) {
    let service = get_network_service();

    // Check if proxy is currently enabled
    let output = Command::new("networksetup")
        .args(["-getwebproxy", &service])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        let enabled = text.contains("Enabled: Yes");
        let points_to_us = text.contains("127.0.0.1") && text.contains("8080");

        if enabled && points_to_us {
            // Proxy is on — check if mitmproxy is actually running
            let running = std::net::TcpStream::connect("127.0.0.1:8080").is_ok();
            if !running {
                // Broken state — show alert
                send_notification(
                    app,
                    "🛡️ CoworkGuard — Action needed",
                    "Your internet may not be working. CoworkGuard was left on when your Mac restarted. Click Start Protection to fix it.",
                );
                // Disable the broken proxy so internet works
                disable_proxy();
            }
        }
    }
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

fn main() {
    let tray = SystemTray::new()
        .with_menu(build_tray_menu(false))
        .with_tooltip("CoworkGuard — AI Privacy Protection");

    tauri::Builder::default()
        .manage(AppState {
            proxy_process:  Mutex::new(None),
            server_process: Mutex::new(None),
            is_running:     Mutex::new(false),
        })
        .system_tray(tray)
        .on_system_tray_event(|app, event| {
            if let SystemTrayEvent::MenuItemClick { id, .. } = event {
                match id.as_str() {
                    "toggle" => {
                        let is_running = *app.state::<AppState>().is_running.lock().unwrap();
                        if is_running {
                            stop_coworkguard(app);
                        } else {
                            start_coworkguard(app);
                        }
                    }
                    "dashboard" => {
                        let _ = tauri::api::shell::open(
                            &app.shell_scope(),
                            "http://localhost:7070",
                            None,
                        );
                    }
                    "about" => {
                        let _ = tauri::api::shell::open(
                            &app.shell_scope(),
                            "https://katherine-holland.github.io/ClaudeCoworkGuard",
                            None,
                        );
                    }
                    "quit" => {
                        // Always clean up before quitting
                        stop_coworkguard(app);
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
        })
        .setup(|app| {
            // Hide from Dock — menubar only app
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Check for broken proxy state from previous session
            let app_handle = app.handle();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(3));
                check_proxy_state_on_startup(&app_handle);
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running CoworkGuard");
}
