#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod lists;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

const TASK_NAME: &str = "PerfSaver";

const NO_WINDOW: u32 = 0x0800_0000;
const HIGH_PERF: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
const ULTIMATE_TEMPLATE: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";

struct AppState {
    sys: Mutex<System>,
    tray_game: Mutex<Option<MenuItem<tauri::Wry>>>,
}

// ---------------------------------------------------------------- utilitaires

fn data_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    let p = PathBuf::from(base).join("PerfSaver");
    let _ = std::fs::create_dir_all(&p);
    p
}

fn load_json<T: for<'de> Deserialize<'de> + Default>(file: &str) -> T {
    std::fs::read_to_string(data_dir().join(file))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_json<T: Serialize>(file: &str, v: &T) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        let _ = std::fs::write(data_dir().join(file), s);
    }
}

fn run(cmd: &str, args: &[&str]) -> (bool, String) {
    match Command::new(cmd).args(args).creation_flags(NO_WINDOW).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s)
        }
        Err(e) => (false, e.to_string()),
    }
}

fn find_guid(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 36 {
        return None;
    }
    for i in 0..=b.len() - 36 {
        let w = &b[i..i + 36];
        let ok = w.iter().enumerate().all(|(j, c)| {
            if [8, 13, 18, 23].contains(&j) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
        if ok {
            return Some(String::from_utf8_lossy(w).to_lowercase());
        }
    }
    None
}

fn lookup<'a>(list: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    list.iter().find(|(n, _)| *n == name).map(|(_, d)| *d)
}

/// Retourne (catégorie, description)
fn categorize(name: &str, exe: &str) -> (&'static str, String) {
    let n = name.to_lowercase();
    let e = exe.to_lowercase();
    if lists::SYSTEM.contains(&n.as_str()) {
        return ("systeme", "Windows / pilote / sécurité".into());
    }
    if let Some(d) = lookup(lists::BLOAT, &n) {
        return ("inutile", d.into());
    }
    if let Some(d) = lookup(lists::HARDWARE, &n) {
        return ("materiel", d.into());
    }
    if let Some(d) = lookup(lists::LAUNCHERS, &n) {
        return ("launcher", d.into());
    }
    if let Some(d) = lookup(lists::HEAVY, &n) {
        return ("appli", d.into());
    }
    if !e.is_empty() && lists::GAME_DIRS.iter().any(|d| e.contains(d)) {
        return ("jeu", "Jeu détecté".into());
    }
    if e.starts_with("c:\\windows\\") {
        return ("systeme", "Composant Windows".into());
    }
    if n.contains("update") || n.contains("updater") {
        return ("inutile", "Programme de mise à jour".into());
    }
    ("autre", String::new())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Détecte ce qui ressemble à un faux processus système ou à un lancement louche.
fn suspicious(name: &str, exe: &str) -> Option<String> {
    let n = name.to_lowercase();
    let e = exe.to_lowercase();
    if !e.is_empty() {
        if let Some((_, dirs)) = lists::IMPERSONATED.iter().find(|(s, _)| *s == n) {
            let parent_ok = dirs.iter().any(|d| {
                e.starts_with(d) && !e[d.len()..].contains('\\')
            });
            if !parent_ok {
                return Some(format!(
                    "Porte le nom d'un processus Windows mais se trouve ailleurs : {exe}"
                ));
            }
        }
        if e.contains("\\appdata\\local\\temp\\") || e.contains("\\windows\\temp\\") {
            return Some("Lancé depuis un dossier temporaire".into());
        }
        if e.contains("\\users\\public\\") {
            return Some("Lancé depuis le dossier Public".into());
        }
        if e.starts_with("c:\\programdata\\") && e.matches('\\').count() == 2 {
            return Some("Exécutable posé directement dans ProgramData".into());
        }
    }
    let known = lists::SYSTEM.contains(&n.as_str())
        || lists::IMPERSONATED.iter().any(|(s, _)| *s == n)
        || e.starts_with("c:\\windows\\");
    if known {
        return None;
    }
    let stem = n.trim_end_matches(".exe");
    for (s, _) in lists::IMPERSONATED {
        let sys = s.trim_end_matches(".exe");
        if stem.len() >= 4 && sys.len() >= 5 {
            let d = levenshtein(stem, sys);
            let max = if sys.len() >= 8 { 2 } else { 1 };
            if d >= 1 && d <= max {
                return Some(format!("Nom très proche de « {s} » (imitation possible)"));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- processus

#[derive(Serialize)]
struct Group {
    name: String,
    label: String,
    exe: String,
    count: usize,
    pids: Vec<u32>,
    cpu: f32,
    mem_mb: f64,
    category: String,
    alert: Option<String>,
}

#[derive(Serialize)]
struct Snapshot {
    cpu: f32,
    ram_used_mb: f64,
    ram_total_mb: f64,
    cores: usize,
    groups: Vec<Group>,
    game_mode: bool,
}

fn cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn refresh(sys: &mut System) {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet),
    );
    sys.refresh_cpu_usage();
    sys.refresh_memory();
}

fn build_groups(sys: &System) -> Vec<Group> {
    let me = std::process::id();
    let nc = cores() as f32;
    let mut map: BTreeMap<String, Group> = BTreeMap::new();
    for (pid, p) in sys.processes() {
        if pid.as_u32() == me || pid.as_u32() == 0 {
            continue;
        }
        let name = p.name().to_string_lossy().to_string();
        let key = name.to_lowercase();
        let exe = p.exe().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
        let g = map.entry(key).or_insert_with(|| {
            let (cat, label) = categorize(&name, &exe);
            Group {
                name: name.clone(),
                label,
                exe: exe.clone(),
                count: 0,
                pids: vec![],
                cpu: 0.0,
                mem_mb: 0.0,
                category: cat.into(),
                alert: None,
            }
        });
        if g.exe.is_empty() && !exe.is_empty() {
            g.exe = exe.clone();
            let (cat, label) = categorize(&name, &exe);
            g.category = cat.into();
            g.label = label;
        }
        if g.alert.is_none() {
            g.alert = suspicious(&name, &exe);
        }
        g.count += 1;
        g.pids.push(pid.as_u32());
        g.cpu += p.cpu_usage() / nc;
        g.mem_mb += p.memory() as f64 / 1_048_576.0;
    }
    let mut v: Vec<Group> = map.into_values().collect();
    v.sort_by(|a, b| b.mem_mb.partial_cmp(&a.mem_mb).unwrap_or(std::cmp::Ordering::Equal));
    v
}

#[tauri::command]
fn get_snapshot(state: tauri::State<AppState>) -> Result<Snapshot, String> {
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    refresh(&mut sys);
    let st: GameState = load_json("state.json");
    Ok(Snapshot {
        cpu: sys.global_cpu_usage(),
        ram_used_mb: (sys.total_memory() - sys.available_memory()) as f64 / 1_048_576.0,
        ram_total_mb: sys.total_memory() as f64 / 1_048_576.0,
        cores: cores(),
        groups: build_groups(&sys),
        game_mode: st.active,
    })
}

fn is_protected(name: &str) -> bool {
    let n = name.to_lowercase();
    lists::SYSTEM.contains(&n.as_str())
}

fn kill_name(sys: &System, name: &str) -> usize {
    if is_protected(name) {
        return 0;
    }
    let me = std::process::id();
    let target = name.to_lowercase();
    let mut n = 0;
    for (pid, p) in sys.processes() {
        if pid.as_u32() == me {
            continue;
        }
        if p.name().to_string_lossy().to_lowercase() == target && p.kill() {
            n += 1;
        }
    }
    n
}

#[tauri::command]
fn kill_group(state: tauri::State<AppState>, name: String) -> Result<usize, String> {
    if is_protected(&name) {
        return Err("Processus protégé : le fermer pourrait faire planter Windows ou ton jeu.".into());
    }
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    refresh(&mut sys);
    Ok(kill_name(&sys, &name))
}

mod win {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::ProcessStatus::K32EmptyWorkingSet;
    use windows_sys::Win32::System::Threading::*;

    pub fn set_priority(pid: u32, class: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_SET_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let ok = SetPriorityClass(h, class) != 0;
            CloseHandle(h);
            ok
        }
    }

    pub fn trim(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, 0, pid);
            if h.is_null() {
                return false;
            }
            let ok = K32EmptyWorkingSet(h) != 0;
            CloseHandle(h);
            ok
        }
    }

    pub const HIGH: u32 = HIGH_PRIORITY_CLASS;
    pub const BELOW: u32 = BELOW_NORMAL_PRIORITY_CLASS;
    pub const NORMAL: u32 = NORMAL_PRIORITY_CLASS;
}

#[tauri::command]
fn set_priority(state: tauri::State<AppState>, name: String, level: String) -> Result<usize, String> {
    let class = match level.as_str() {
        "high" => win::HIGH,
        "below" => win::BELOW,
        _ => win::NORMAL,
    };
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    refresh(&mut sys);
    let t = name.to_lowercase();
    let mut n = 0;
    for (pid, p) in sys.processes() {
        if p.name().to_string_lossy().to_lowercase() == t && win::set_priority(pid.as_u32(), class) {
            n += 1;
        }
    }
    Ok(n)
}

#[tauri::command]
fn free_ram(state: tauri::State<AppState>) -> Result<f64, String> {
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    Ok(trim_all(&mut sys))
}

/// Vide la mémoire de travail de tous les processus sauf les jeux. Retourne les Mo libérés.
fn trim_all(sys: &mut System) -> f64 {
    refresh(sys);
    let before = sys.available_memory();
    for g in build_groups(sys) {
        if g.category == "jeu" {
            continue;
        }
        for pid in g.pids {
            win::trim(pid);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    sys.refresh_memory();
    (sys.available_memory() as f64 - before as f64).max(0.0) / 1_048_576.0
}

// ---------------------------------------------------------------- services

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawSvc {
    name: Option<String>,
    display_name: Option<String>,
    state: Option<String>,
    start_mode: Option<String>,
    path_name: Option<String>,
}

#[derive(Serialize)]
struct Svc {
    name: String,
    display: String,
    running: bool,
    start: String,
    path: String,
    third_party: bool,
    gaming_note: Option<String>,
    alert: Option<String>,
}

fn query_services() -> Vec<Svc> {
    let script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
        Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Json -Compress";
    let (_, out) = run(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    );
    let start = out.find('[').unwrap_or(0);
    let raw: Vec<RawSvc> = serde_json::from_str(out[start..].trim()).unwrap_or_default();
    let mut v: Vec<Svc> = raw
        .into_iter()
        .filter_map(|r| {
            let name = r.name?;
            let path = r.path_name.unwrap_or_default();
            let pl = path.to_lowercase();
            let pl_clean = pl.trim_start_matches('"');
            let third_party = !pl_clean.starts_with("c:\\windows\\") && !pl.is_empty();
            let mut gaming_note = lists::SERVICES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(&name))
                .map(|(_, d)| d.to_string());
            if gaming_note.is_none() && third_party && name.to_lowercase().contains("update") {
                gaming_note = Some("Service de mise à jour d'un logiciel".into());
            }
            let exe_part = if pl.starts_with('"') {
                pl_clean.split('"').next().unwrap_or("").to_string()
            } else {
                pl.split(".exe").next().map(|s| format!("{s}.exe")).unwrap_or_default()
            };
            let exe_name = exe_part.rsplit('\\').next().unwrap_or("").to_string();
            let mut alert = if exe_part.is_empty() { None } else { suspicious(&exe_name, &exe_part) };
            if alert.is_none() && (pl.contains("\\temp\\") || pl.contains("\\appdata\\")) {
                alert = Some("Service installé dans un dossier utilisateur (inhabituel)".into());
            }
            Some(Svc {
                display: r.display_name.unwrap_or_else(|| name.clone()),
                running: r.state.as_deref() == Some("Running"),
                start: r.start_mode.unwrap_or_default(),
                path,
                third_party,
                gaming_note,
                alert,
                name,
            })
        })
        .collect();
    v.sort_by(|a, b| a.display.to_lowercase().cmp(&b.display.to_lowercase()));
    v
}

#[tauri::command]
async fn get_services() -> Result<Vec<Svc>, String> {
    Ok(query_services())
}

fn sc(action: &str, name: &str) -> Result<(), String> {
    let (ok, out) = run("sc.exe", &[action, name]);
    if ok || out.contains("1062") || out.contains("1056") {
        Ok(())
    } else {
        Err(out.lines().filter(|l| !l.trim().is_empty()).last().unwrap_or("échec").trim().to_string())
    }
}

#[tauri::command]
async fn set_service(name: String, run_it: bool) -> Result<(), String> {
    sc(if run_it { "start" } else { "stop" }, &name)
}

// ---------------------------------------------------------------- démarrage

#[derive(Serialize)]
struct StartupItem {
    id: String,
    name: String,
    command: String,
    location: String,
    enabled: bool,
    category: String,
    label: String,
    alert: Option<String>,
}

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN32: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

fn hive(h: &str) -> winreg::RegKey {
    use winreg::enums::*;
    winreg::RegKey::predef(if h == "HKCU" { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE })
}

fn approved_enabled(h: &str, kind: &str, name: &str) -> bool {
    hive(h)
        .open_subkey(format!("{APPROVED}\\{kind}"))
        .and_then(|k| k.get_raw_value(name))
        .map(|v| v.bytes.first().map(|b| b & 1 == 0).unwrap_or(true))
        .unwrap_or(true)
}

fn exe_from_command(cmd: &str) -> String {
    let c = cmd.trim();
    if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        let l = c.to_lowercase();
        match l.find(".exe") {
            Some(i) => c[..i + 4].to_string(),
            None => c.split(' ').next().unwrap_or("").to_string(),
        }
    }
}

fn startup_alert(cmd: &str) -> Option<String> {
    let l = cmd.to_lowercase();
    if l.contains("\\temp\\") {
        return Some("Se lance depuis un dossier temporaire".into());
    }
    if l.contains("mshta") || l.contains("wscript") || l.contains("cscript") || l.contains(".vbs") {
        return Some("Lance un script au démarrage (méthode souvent utilisée par des malwares)".into());
    }
    if l.contains("powershell") && (l.contains("-enc") || l.contains("-e ") || l.contains("hidden")) {
        return Some("Commande PowerShell cachée ou encodée au démarrage".into());
    }
    let exe = exe_from_command(cmd);
    let name = exe.rsplit('\\').next().unwrap_or("").to_string();
    suspicious(&name, &exe)
}

#[tauri::command]
fn get_startup() -> Result<Vec<StartupItem>, String> {
    let mut items = vec![];
    for (h, path, kind, loc) in [
        ("HKCU", RUN, "Run", "Registre (ton compte)"),
        ("HKLM", RUN, "Run", "Registre (tous les comptes)"),
        ("HKLM", RUN32, "Run32", "Registre 32 bits"),
    ] {
        if let Ok(k) = hive(h).open_subkey(path) {
            for (name, val) in k.enum_values().flatten() {
                let command = val.to_string();
                let exe = exe_from_command(&command);
                let fname = exe.rsplit('\\').next().unwrap_or("").to_string();
                let (cat, label) = categorize(&fname, &exe);
                items.push(StartupItem {
                    id: format!("{h}|{kind}|{name}"),
                    enabled: approved_enabled(h, kind, &name),
                    alert: startup_alert(&command),
                    name,
                    command,
                    location: loc.into(),
                    category: cat.into(),
                    label,
                });
            }
        }
    }
    let folders = [
        ("HKCU", std::env::var("APPDATA").unwrap_or_default() + r"\Microsoft\Windows\Start Menu\Programs\Startup", "Dossier Démarrage (ton compte)"),
        ("HKLM", std::env::var("ProgramData").unwrap_or_default() + r"\Microsoft\Windows\Start Menu\Programs\StartUp", "Dossier Démarrage (tous)"),
    ];
    for (h, dir, loc) in folders {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                if fname.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                let stem = fname.rsplit_once('.').map(|(a, _)| a).unwrap_or(&fname).to_lowercase() + ".exe";
                let (cat, label) = categorize(&stem, "");
                let command = e.path().to_string_lossy().to_string();
                items.push(StartupItem {
                    id: format!("{h}|StartupFolder|{fname}"),
                    enabled: approved_enabled(h, "StartupFolder", &fname),
                    alert: startup_alert(&command),
                    name: fname,
                    command,
                    location: loc.into(),
                    category: cat.into(),
                    label,
                });
            }
        }
    }
    Ok(items)
}

#[tauri::command]
fn set_startup(id: String, enabled: bool) -> Result<(), String> {
    let mut parts = id.splitn(3, '|');
    let (h, kind, name) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    let (key, _) = hive(h)
        .create_subkey(format!("{APPROVED}\\{kind}"))
        .map_err(|e| format!("Accès refusé au registre : {e}"))?;
    let mut data = vec![0u8; 12];
    data[0] = if enabled { 0x02 } else { 0x03 };
    key.set_raw_value(
        name,
        &winreg::RegValue { bytes: data.into(), vtype: winreg::enums::RegType::REG_BINARY },
    )
    .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- mode jeu

#[derive(Serialize, Deserialize, Default)]
struct GameState {
    active: bool,
    stopped_services: Vec<String>,
    prev_power: Option<String>,
    adjusted_pids: Vec<u32>,
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    kill: Vec<String>,
    services: Vec<String>,
    ultimate_scheme: Option<String>,
    options: Option<Options>,
    #[serde(default)]
    autostart_asked: bool,
    #[serde(default)]
    terms_accepted: Option<String>,
    #[serde(default)]
    auto_update: Option<bool>,
}

const TERMS_VERSION: &str = "2026-11-07.2";

#[tauri::command]
fn accept_terms() {
    let mut cfg: Config = load_json("config.json");
    cfg.terms_accepted = Some(TERMS_VERSION.into());
    save_json("config.json", &cfg);
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

#[tauri::command]
fn app_info() -> serde_json::Value {
    serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "terms": TERMS_VERSION, "data_dir": data_dir().to_string_lossy() })
}

#[derive(Serialize, Deserialize, Clone)]
struct Options {
    power: bool,
    trim: bool,
    boost_games: bool,
    lower_background: bool,
}

#[derive(Deserialize)]
struct GameRequest {
    kill: Vec<String>,
    services: Vec<String>,
    options: Options,
}

#[derive(Serialize, Default)]
struct Report {
    killed: Vec<String>,
    services: Vec<String>,
    power: Option<String>,
    ram_freed_mb: f64,
    boosted: Vec<String>,
    lowered: usize,
    errors: Vec<String>,
}

#[tauri::command]
fn get_config() -> Config {
    load_json("config.json")
}

fn activate_power(cfg: &mut Config) -> Result<String, String> {
    if run("powercfg", &["/setactive", HIGH_PERF]).0 {
        return Ok("Hautes performances".into());
    }
    if let Some(g) = cfg.ultimate_scheme.clone() {
        if run("powercfg", &["/setactive", &g]).0 {
            return Ok("Performances optimales".into());
        }
    }
    let (_, out) = run("powercfg", &["-duplicatescheme", ULTIMATE_TEMPLATE]);
    if let Some(g) = find_guid(&out) {
        if run("powercfg", &["/setactive", &g]).0 {
            cfg.ultimate_scheme = Some(g);
            return Ok("Performances optimales".into());
        }
    }
    Err("Impossible de changer le mode d'alimentation (PC portable verrouillé ?)".into())
}

#[tauri::command]
async fn game_mode_on(state: tauri::State<'_, AppState>, req: GameRequest) -> Result<Report, String> {
    let mut rep = Report::default();
    let mut st: GameState = load_json("state.json");
    let mut cfg: Config = load_json("config.json");
    cfg.kill = req.kill.clone();
    cfg.services = req.services.clone();
    cfg.options = Some(req.options.clone());

    // 1. fermer les applis choisies
    {
        let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
        refresh(&mut sys);
        for n in &req.kill {
            let k = kill_name(&sys, n);
            if k > 0 {
                rep.killed.push(n.clone());
            }
        }
    }

    // 2. arrêter les services (on garde la liste pour les relancer)
    let running: HashSet<String> = query_services()
        .into_iter()
        .filter(|s| s.running)
        .map(|s| s.name.to_lowercase())
        .collect();
    for s in &req.services {
        if !running.contains(&s.to_lowercase()) {
            continue;
        }
        match sc("stop", s) {
            Ok(()) => {
                rep.services.push(s.clone());
                if !st.stopped_services.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                    st.stopped_services.push(s.clone());
                }
            }
            Err(e) => rep.errors.push(format!("Service {s} : {e}")),
        }
    }

    // 3. alimentation
    if req.options.power {
        if !st.active || st.prev_power.is_none() {
            st.prev_power = find_guid(&run("powercfg", &["/getactivescheme"]).1);
        }
        match activate_power(&mut cfg) {
            Ok(p) => rep.power = Some(p),
            Err(e) => rep.errors.push(e),
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(600));
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    refresh(&mut sys);
    let groups = build_groups(&sys);

    // 4. priorités
    for g in &groups {
        let class = match g.category.as_str() {
            "jeu" if req.options.boost_games => Some(win::HIGH),
            "appli" | "materiel" | "launcher" | "inutile" if req.options.lower_background => {
                Some(win::BELOW)
            }
            _ => None,
        };
        if let Some(c) = class {
            let mut any = false;
            for pid in &g.pids {
                if win::set_priority(*pid, c) {
                    any = true;
                    st.adjusted_pids.push(*pid);
                }
            }
            if any {
                if c == win::HIGH {
                    rep.boosted.push(g.name.clone());
                } else {
                    rep.lowered += 1;
                }
            }
        }
    }

    // 5. RAM
    if req.options.trim {
        rep.ram_freed_mb = trim_all(&mut sys);
    }

    st.active = true;
    save_json("state.json", &st);
    save_json("config.json", &cfg);
    Ok(rep)
}

#[tauri::command]
async fn game_mode_off() -> Result<Report, String> {
    Ok(restore())
}

fn restore() -> Report {
    let mut rep = Report::default();
    let st: GameState = load_json("state.json");
    for s in &st.stopped_services {
        match sc("start", s) {
            Ok(()) => rep.services.push(s.clone()),
            Err(e) => rep.errors.push(format!("Service {s} : {e}")),
        }
    }
    if let Some(p) = &st.prev_power {
        if run("powercfg", &["/setactive", p]).0 {
            rep.power = Some("Mode d'alimentation d'origine".into());
        }
    }
    for pid in &st.adjusted_pids {
        if win::set_priority(*pid, win::NORMAL) {
            rep.lowered += 1;
        }
    }
    save_json("state.json", &GameState::default());
    rep
}

#[tauri::command]
fn open_location(path: String) -> Result<(), String> {
    Command::new("explorer.exe")
        .arg(format!("/select,{path}"))
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- démarrage auto

fn xml_escape(v: &str) -> String {
    v.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[tauri::command]
fn get_autostart() -> bool {
    run("schtasks.exe", &["/query", "/tn", TASK_NAME]).0
}

/// Tâche planifiée « à l'ouverture de session, avec les droits admin » :
/// un raccourci dans « Run » ne peut pas lancer une appli admin sans demande UAC.
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    let mut cfg: Config = load_json("config.json");
    cfg.autostart_asked = true;
    save_json("config.json", &cfg);
    if !enabled {
        if get_autostart() {
            let (ok, out) = run("schtasks.exe", &["/delete", "/tn", TASK_NAME, "/f"]);
            if !ok {
                return Err(out.trim().to_string());
            }
        }
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Lance Perf Saver dans la zone de notification à l'ouverture de session.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowHardTerminate>true</AllowHardTerminate>
    <Priority>7</Priority>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>--tray</Arguments></Exec></Actions>
</Task>"#,
        user = xml_escape(&user),
        exe = xml_escape(&exe.to_string_lossy())
    );
    let path = data_dir().join("autostart.xml");
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let p = path.to_string_lossy().to_string();
    let (ok, out) = run("schtasks.exe", &["/create", "/tn", TASK_NAME, "/xml", &p, "/f"]);
    let _ = std::fs::remove_file(&path);
    if ok {
        Ok(())
    } else {
        Err(format!("Impossible de créer la tâche de démarrage : {}", out.trim()))
    }
}

// ---------------------------------------------------------------- mises à jour

/// Manifeste publié par le site de téléchargement (généré par build.sh).
const UPDATE_URL: &str = "https://perf-saver.vercel.app/latest.json";

#[derive(Serialize, Deserialize, Clone)]
struct UpdateInfo {
    version: String,
    url: String,
    sha256: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    available: bool,
}

fn parse_ver(v: &str) -> (u32, u32, u32) {
    let mut it = v.trim().trim_start_matches('v').split('.').map(|x| {
        x.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0)
    });
    (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// curl.exe est fourni avec Windows 10 (1803+) et 11 : pas besoin d'embarquer une pile TLS.
fn curl(args: &[&str]) -> Result<Vec<u8>, String> {
    let o = Command::new("curl.exe")
        .args(["-fsSL", "--proto", "=https", "--tlsv1.2", "--retry", "2"])
        .args(args)
        .creation_flags(NO_WINDOW)
        .output()
        .map_err(|e| format!("curl indisponible : {e}"))?;
    if o.status.success() {
        Ok(o.stdout)
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

#[tauri::command]
async fn check_update() -> Result<UpdateInfo, String> {
    let body = curl(&["--max-time", "10", UPDATE_URL]).map_err(|e| format!("Vérification impossible : {e}"))?;
    let mut info: UpdateInfo =
        serde_json::from_slice(&body).map_err(|_| "Réponse de mise à jour invalide".to_string())?;
    if info.url.starts_with('/') {
        let origin = UPDATE_URL.splitn(4, '/').take(3).collect::<Vec<_>>().join("/");
        info.url = format!("{origin}{}", info.url);
    }
    info.available = parse_ver(&info.version) > parse_ver(env!("CARGO_PKG_VERSION"));
    Ok(info)
}

/// Télécharge l'installeur, vérifie son SHA-256, le lance en silencieux puis quitte.
/// L'installeur ferme l'ancienne version, remplace les fichiers et relance l'app.
#[tauri::command]
async fn install_update(app: AppHandle, info: UpdateInfo) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    if !info.url.starts_with("https://") {
        return Err("Adresse de téléchargement refusée".into());
    }
    let dir = std::env::temp_dir().join("PerfSaverUpdate");
    let _ = std::fs::create_dir_all(&dir);
    let (a, b, c) = parse_ver(&info.version);
    let path = dir.join(format!("PerfSaver-Setup-{a}.{b}.{c}.exe"));
    let p = path.to_string_lossy().to_string();
    curl(&["--max-time", "300", "-o", &p, &info.url]).map_err(|e| format!("Téléchargement échoué : {e}"))?;
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    let hash: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    if !hash.eq_ignore_ascii_case(info.sha256.trim()) {
        let _ = std::fs::remove_file(&path);
        return Err("Le fichier téléchargé ne correspond pas à l'empreinte attendue : mise à jour annulée.".into());
    }
    let st: GameState = load_json("state.json");
    if st.active {
        restore();
    }
    Command::new(&path)
        .args(["/S", "/UPDATE"])
        .spawn()
        .map_err(|e| format!("Impossible de lancer l'installeur : {e}"))?;
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn set_auto_update(enabled: bool) {
    let mut cfg: Config = load_json("config.json");
    cfg.auto_update = Some(enabled);
    save_json("config.json", &cfg);
}

// ---------------------------------------------------------------- zone de notification

#[tauri::command]
fn set_tray_state(state: tauri::State<AppState>, active: bool) {
    if let Ok(g) = state.tray_game.lock() {
        if let Some(item) = g.as_ref() {
            let _ = item.set_text(if active { "Désactiver le mode jeu" } else { "Activer le mode jeu" });
        }
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Ouvrir Perf Saver", true, None::<&str>)?;
    let active: GameState = load_json("state.json");
    let game = MenuItem::with_id(
        app,
        "game",
        if active.active { "Désactiver le mode jeu" } else { "Activer le mode jeu" },
        true,
        None::<&str>,
    )?;
    let ram = MenuItem::with_id(app, "ram", "Libérer la RAM", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quitter", true, None::<&str>)?;
    let s1 = PredefinedMenuItem::separator(app)?;
    let s2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &s1, &game, &ram, &s2, &quit])?;
    if let Ok(mut g) = app.state::<AppState>().tray_game.lock() {
        *g = Some(game.clone());
    }
    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Perf Saver")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id.as_ref() {
            "open" => show_main(app),
            "game" => {
                let _ = app.emit("tray-game", ());
            }
            "ram" => {
                let _ = app.emit("tray-ram", ());
            }
            "quit" => {
                let st: GameState = load_json("state.json");
                if st.active {
                    restore();
                }
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn main() {
    let mut sys = System::new();
    refresh(&mut sys);
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .manage(AppState { sys: Mutex::new(sys), tray_game: Mutex::new(None) })
        .setup(|app| {
            setup_tray(app)?;
            let hidden = std::env::args().any(|a| a == "--tray");
            if !hidden {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|w, ev| {
            // Fermer la fenêtre = réduire dans la zone de notification
            if let WindowEvent::CloseRequested { api, .. } = ev {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            kill_group,
            set_priority,
            free_ram,
            get_services,
            set_service,
            get_startup,
            set_startup,
            get_config,
            game_mode_on,
            game_mode_off,
            open_location,
            get_autostart,
            set_autostart,
            set_tray_state,
            accept_terms,
            app_info,
            quit_app,
            check_update,
            install_update,
            set_auto_update
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Perf Saver");
}
