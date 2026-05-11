// CoworkGuard — macOS Menubar App
// © 2026 Katherine Weston. MIT + Commons Clause.

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
    proxy_process:              Mutex<Option<Child>>,
    server_process:             Mutex<Option<Child>>,
    skill_scanner_process:      Mutex<Option<Child>>,
    clipboard_monitor_process:  Mutex<Option<Child>>,
    file_write_monitor_process: Mutex<Option<Child>>,
    agent_guard_process:        Mutex<Option<Child>>,
    model_monitor_process:      Mutex<Option<Child>>,
    is_running:                 Mutex<bool>,
    quiet_mode:                 Mutex<bool>,
}

fn find_mitmproxy() -> String {
    let candidates = [
        "/opt/homebrew/bin/mitmdump",
        "/usr/local/bin/mitmdump",
        "/Library/Frameworks/Python.framework/Versions/3.14/bin/mitmdump",
        "/Library/Frameworks/Python.framework/Versions/3.13/bin/mitmdump",
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/mitmdump",
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/mitmdump",
    ];
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    "mitmdump".to_string()
}

fn find_python() -> String {
    let candidates = [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3",
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

fn find_install_dir(app: &AppHandle) -> PathBuf {
    // Use Tauri's resource_dir() — the authoritative location for bundled files.
    // Falls back to manual path construction and home directory for shell installs.
    if let Ok(res_dir) = app.path().resource_dir() {
        if res_dir.join("proxy.py").exists() {
            return res_dir;
        }
        // Tauri 2.x may place resources in a _up_ subdirectory
        let up = res_dir.join("_up_");
        if up.join("proxy.py").exists() {
            return up;
        }
    }
    // Manual bundle path fallback
    if let Ok(exe) = std::env::current_exe() {
        let bundle_resources = exe
            .parent().unwrap_or(&exe)
            .parent().unwrap_or(&exe)
            .join("Resources");
        if bundle_resources.join("proxy.py").exists() {
            return bundle_resources;
        }
    }
    // Shell install fallback
    let home = std::env::var("HOME").unwrap_or_default();
    let home_path = std::path::Path::new(&home);
    for dir in &["ClaudeCoworkGuard", "CoworkGuard"] {
        let p = home_path.join(dir);
        if p.join("proxy.py").exists() {
            return p;
        }
    }
    home_path.join("ClaudeCoworkGuard")
}

fn kill_port(port: u16) {
    let output = Command::new("lsof")
        .args(["-ti", &format!(":{}", port)])
        .output();
    if let Ok(out) = output {
        let pids = String::from_utf8_lossy(&out.stdout);
        for pid in pids.split_whitespace() {
            let _ = Command::new("kill").args(["-9", pid]).output();
        }
    }
}


fn install_dependencies(python_bin: &str, dir: &std::path::Path) -> bool {
    // Run pip install -r requirements.txt before starting any Python process.
    // This ensures flask, flask-cors, mitmproxy, watchdog are present on the
    // Python that the app will actually use — not just whichever python3 is on PATH.
    let req = dir.join("requirements.txt");
    if !req.exists() {
        eprintln!("[CoworkGuard] requirements.txt not found — skipping dep check");
        return true; // Don't block startup if requirements.txt is missing
    }
    eprintln!("[CoworkGuard] Installing dependencies from requirements.txt...");
    let result = Command::new(python_bin)
        .args(["-m", "pip", "install", "-r", req.to_str().unwrap_or("requirements.txt"),
               "--quiet", "--disable-pip-version-check"])
        .output();
    match result {
        Ok(out) => {
            if out.status.success() {
                eprintln!("[CoworkGuard] Dependencies installed OK");
                true
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!("[CoworkGuard] pip install failed: {}", stderr);
                // Try with --break-system-packages for Homebrew/system Python
                let result2 = Command::new(python_bin)
                    .args(["-m", "pip", "install", "-r", req.to_str().unwrap_or("requirements.txt"),
                           "--quiet", "--disable-pip-version-check", "--break-system-packages"])
                    .output();
                result2.map(|o| o.status.success()).unwrap_or(false)
            }
        }
        Err(e) => {
            eprintln!("[CoworkGuard] pip not available: {}", e);
            false // Don't block — let server.py fail with a clear error
        }
    }
}

fn start_coworkguard(app: &AppHandle) {
    let dir = find_install_dir(app);
    if !dir.join("proxy.py").exists() {
        eprintln!("[CoworkGuard] proxy.py not found in {:?}", dir);
        if let Some(tray) = app.tray_by_id("main") {
            let _ = tray.set_tooltip(Some("CoworkGuard: Installation not found — please reinstall."));
        }
        return;
    }
    let mitmproxy_bin = find_mitmproxy();
    let python_bin = find_python();
    let app_handle = app.clone();
    std::thread::spawn(move || {
        let state = app_handle.state::<AppState>();
        kill_port(8080);
        kill_port(7070);
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Install/verify Python dependencies before launching any Python process
        install_dependencies(&python_bin, &dir);
        let proxy = Command::new(&mitmproxy_bin)
            .args(["-s", "proxy.py", "--listen-port", "8080", "--quiet"])
            .current_dir(&dir)
            .env("PYTHONPATH", &dir)
            .spawn();
        match proxy {
            Ok(child) => { *state.proxy_process.lock().unwrap() = Some(child); }
            Err(e) => { eprintln!("[CoworkGuard] mitmdump failed: {}", e); return; }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        let server = Command::new(&python_bin)
            .args(["server.py"])
            .current_dir(&dir)
            .env("PYTHONPATH", &dir)
            .spawn();
        match server {
            Ok(child) => { *state.server_process.lock().unwrap() = Some(child); }
            Err(e) => eprintln!("[CoworkGuard] server.py failed: {}", e),
        }
        let skill_scanner = Command::new(&python_bin)
            .args(["skill_scanner.py"])
            .current_dir(&dir)
            .spawn();
        match skill_scanner {
            Ok(child) => { *state.skill_scanner_process.lock().unwrap() = Some(child); }
            Err(e) => eprintln!("[CoworkGuard] skill_scanner.py failed: {}", e),
        }
        let clipboard_monitor = Command::new(&python_bin)
            .args(["clipboard_monitor.py"])
            .current_dir(&dir)
            .spawn();
        match clipboard_monitor {
            Ok(child) => { *state.clipboard_monitor_process.lock().unwrap() = Some(child); }
            Err(e) => eprintln!("[CoworkGuard] clipboard_monitor.py failed: {}", e),
        }
        let file_write_monitor = Command::new(&python_bin)
            .args(["file_write_monitor.py"])
            .current_dir(&dir)
            .spawn();
        match file_write_monitor {
            Ok(child) => { *state.file_write_monitor_process.lock().unwrap() = Some(child); }
            Err(e) => eprintln!("[CoworkGuard] file_write_monitor.py failed: {}", e),
        }
        let agent_guard = Command::new(&python_bin)
            .args(["-m", "actor_monitor.agent_guard"])
            .current_dir(&dir)
            .env("PYTHONPATH", &dir)
            .spawn();
        match agent_guard {
            Ok(child) => { *state.agent_guard_process.lock().unwrap() = Some(child); }
            Err(e) => eprintln!("[CoworkGuard] agent_guard failed: {}", e),
        }
        let model_monitor = Command::new(&python_bin)
            .args(["-m", "actor_monitor.model_monitor"])
            .current_dir(&dir)
            .env("PYTHONPATH", &dir)
            .spawn();
        match model_monitor {
            Ok(child) => { *state.model_monitor_process.lock().unwrap() = Some(child); }
            Err(e) => eprintln!("[CoworkGuard] model_monitor failed: {}", e),
        }
        enable_proxy();
        *state.is_running.lock().unwrap() = true;
        let _ = rebuild_menu(&app_handle, true);
    });
}

fn stop_coworkguard(app: &AppHandle) {
    let state = app.state::<AppState>();
    disable_proxy();
    if let Some(mut c) = state.proxy_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.server_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.skill_scanner_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.clipboard_monitor_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.file_write_monitor_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.agent_guard_process.lock().unwrap().take() { let _ = c.kill(); }
    if let Some(mut c) = state.model_monitor_process.lock().unwrap().take() { let _ = c.kill(); }
    let _ = Command::new("pkill").args(["-f", "mitmdump"]).output();
    let _ = Command::new("pkill").args(["-f", "mitmproxy"]).output();
    let _ = Command::new("pkill").args(["-f", "server.py"]).output();
    let _ = Command::new("pkill").args(["-f", "skill_scanner.py"]).output();
    let _ = Command::new("pkill").args(["-f", "clipboard_monitor.py"]).output();
    let _ = Command::new("pkill").args(["-f", "file_write_monitor.py"]).output();
    let _ = Command::new("pkill").args(["-f", "agent_guard"]).output();
    let _ = Command::new("pkill").args(["-f", "model_monitor"]).output();
    std::thread::sleep(std::time::Duration::from_millis(500));
    kill_port(8080);
    kill_port(7070);
    *state.is_running.lock().unwrap() = false;
    let _ = rebuild_menu(app, false);
    eprintln!("[CoworkGuard] Stopped cleanly");
}

fn build_menu(app: &AppHandle, running: bool, quiet: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let toggle_label = if running { "Stop Protection" } else { "Start Protection" };
    let status_label = if running { "● PROTECTION ON" } else { "○ Protection off" };
    let quiet_label  = if quiet { "✓ Quiet Mode — notifications off" } else { "Quiet Mode" };
    // Use a unique prefix per build so re-registering IDs doesn't panic in Tauri 2.x.
    // The on_menu_event handler matches on the suffix after the first '-'.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let toggle_id   = format!("{}-toggle",    ts);
    let dash_id     = format!("{}-dashboard", ts);
    let quiet_id    = format!("{}-quiet",     ts);
    let about_id    = format!("{}-about",     ts);
    let quit_id     = format!("{}-quit",      ts);
    let menu       = Menu::new(app)?;
    let status     = MenuItem::new(app, status_label, false, None::<&str>)?;
    let sep1       = PredefinedMenuItem::separator(app)?;
    let toggle     = MenuItem::with_id(app, &toggle_id,   toggle_label,        true, None::<&str>)?;
    let dash       = MenuItem::with_id(app, &dash_id,     "Open Dashboard →",  true, None::<&str>)?;
    let sep2       = PredefinedMenuItem::separator(app)?;
    let quiet_item = MenuItem::with_id(app, &quiet_id,    quiet_label,         true, None::<&str>)?;
    let sep3       = PredefinedMenuItem::separator(app)?;
    let about      = MenuItem::with_id(app, &about_id,    "About CoworkGuard", true, None::<&str>)?;
    let quit       = MenuItem::with_id(app, &quit_id,     "Quit",              true, None::<&str>)?;
    menu.append(&status)?;
    menu.append(&sep1)?;
    menu.append(&toggle)?;
    menu.append(&dash)?;
    menu.append(&sep2)?;
    menu.append(&quiet_item)?;
    menu.append(&sep3)?;
    menu.append(&about)?;
    menu.append(&quit)?;
    Ok(menu)
}

fn rebuild_menu(app: &AppHandle, running: bool) -> tauri::Result<()> {
    let app = app.clone();
    // Tray/menu APIs must run on the main thread. Calling them from a
    // background thread panics inside tao's event loop dispatcher.
    let _ = app.run_on_main_thread(move || {
        let quiet = *app.state::<AppState>().quiet_mode.lock().unwrap();
        if let Some(tray) = app.tray_by_id("main") {
            if let Ok(menu) = build_menu(&app, running, quiet) {
                let _ = tray.set_menu(Some(menu));
            }
            let _ = tray.set_tooltip(Some(if running {
                "CoworkGuard — Protection ON"
            } else {
                "CoworkGuard — Click to start"
            }));
        }
    });
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
            proxy_process:              Mutex::new(None),
            server_process:             Mutex::new(None),
            skill_scanner_process:      Mutex::new(None),
            clipboard_monitor_process:  Mutex::new(None),
            file_write_monitor_process: Mutex::new(None),
            agent_guard_process:        Mutex::new(None),
            model_monitor_process:      Mutex::new(None),
            is_running:                 Mutex::new(false),
            quiet_mode:                 Mutex::new(false),
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let menu = build_menu(app.handle(), false, false)?;
            let icon = tauri::image::Image::from_bytes(
                include_bytes!("../icons/tray-icon.png")
            )?;
            TrayIconBuilder::with_id("main")
                .icon(icon)
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| {
                    // IDs are formatted as "{timestamp}-{action}" to avoid duplicate
                    // registration panics in Tauri 2.x. Match on the suffix only.
                    let id = event.id().as_ref();
                    let action = id.splitn(2, '-').nth(1).unwrap_or(id);
                    match action {
                        "toggle" => {
                            let running = *app.state::<AppState>().is_running.lock().unwrap();
                            if running { stop_coworkguard(app); } else { start_coworkguard(app); }
                        }
                        "dashboard" => { let _ = open::that("http://localhost:7070"); }
                        "quiet" => {
                            let state = app.state::<AppState>();
                            let new_quiet = {
                                let mut quiet = state.quiet_mode.lock().unwrap();
                                *quiet = !*quiet;
                                *quiet
                            };
                            let is_running = *state.is_running.lock().unwrap();
                            let _ = rebuild_menu(app, is_running);
                            let settings_dir = std::path::Path::new(
                                &std::env::var("HOME").unwrap_or_default()
                            ).join(".coworkguard");
                            let _ = std::fs::create_dir_all(&settings_dir);
                            let settings_path = settings_dir.join("settings.json");
                            let existing = std::fs::read_to_string(&settings_path).unwrap_or_default();
                            let mut obj: serde_json::Value = serde_json::from_str(&existing)
                                .unwrap_or_else(|_| serde_json::json!({}));
                            if let Some(map) = obj.as_object_mut() {
                                map.insert("quiet_mode".to_string(), serde_json::Value::Bool(new_quiet));
                            }
                            if let Ok(content) = serde_json::to_string_pretty(&obj) {
                                let _ = std::fs::write(settings_path, content);
                            }
                        }
                        "about" => { let _ = open::that("https://coworkguard.com"); }
                        "quit" => { stop_coworkguard(app); std::process::exit(0); }
                        _ => {}
                    }
                })
                .build(app)?;
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
