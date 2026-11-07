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
    gpu: Mutex<Option<gpu::Gpu>>,
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
    if let Some(d) = lookup(lists::KEEP, &n) {
        return ("protege", d.into());
    }
    if lists::GAMES.contains(&n.as_str()) {
        return ("jeu", "Jeu".into());
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
    /// Possède une fenêtre visible (application ouverte par l'utilisateur).
    has_window: bool,
}

// ---------------------------------------------------------------- carte graphique

/// Utilisation 3D et mémoire vidéo, lues via les compteurs de performances
/// Windows (les mêmes que le Gestionnaire des tâches).
mod gpu {
    use serde::Serialize;
    use windows_sys::Win32::System::Performance::*;

    #[derive(Serialize, Clone)]
    pub struct GpuInfo {
        pub name: String,
        pub util3d: f64,
        pub vram_used_mb: f64,
        pub vram_total_mb: f64,
    }

    pub struct Gpu {
        query: PDH_HQUERY,
        engine: PDH_HCOUNTER,
        memory: PDH_HCOUNTER,
        name: String,
        total_mb: f64,
    }
    // Les handles PDH ne sont utilisés que derrière un Mutex.
    unsafe impl Send for Gpu {}

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Carte graphique principale (celle qui a le plus de mémoire dédiée), lue dans le registre.
    fn adapter() -> (String, f64) {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
        let mut best = (String::from("Carte graphique"), 0f64);
        if let Ok(k) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(base) {
            for sub in k.enum_keys().flatten() {
                let Ok(a) = k.open_subkey(&sub) else { continue };
                let name: String = a.get_value("DriverDesc").unwrap_or_default();
                let mem: u64 = a
                    .get_value::<u64, _>("HardwareInformation.qwMemorySize")
                    .ok()
                    .or_else(|| {
                        a.get_raw_value("HardwareInformation.MemorySize").ok().and_then(|v| {
                            let b = &v.bytes;
                            (b.len() >= 4).then(|| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
                        })
                    })
                    .unwrap_or(0);
                let mb = mem as f64 / 1_048_576.0;
                if !name.is_empty() && mb > best.1 {
                    best = (name, mb);
                }
            }
        }
        best
    }

    impl Gpu {
        pub fn new() -> Option<Gpu> {
            unsafe {
                let mut q: PDH_HQUERY = std::ptr::null_mut();
                if PdhOpenQueryW(std::ptr::null(), 0, &mut q) != 0 {
                    return None;
                }
                let (mut e, mut m): (PDH_HCOUNTER, PDH_HCOUNTER) = (std::ptr::null_mut(), std::ptr::null_mut());
                let pe = wide("\\GPU Engine(*engtype_3D)\\Utilization Percentage");
                let pm = wide("\\GPU Adapter Memory(*)\\Dedicated Usage");
                if PdhAddEnglishCounterW(q, pe.as_ptr(), 0, &mut e) != 0 || PdhAddEnglishCounterW(q, pm.as_ptr(), 0, &mut m) != 0 {
                    PdhCloseQuery(q);
                    return None;
                }
                PdhCollectQueryData(q);
                let (name, total_mb) = adapter();
                Some(Gpu { query: q, engine: e, memory: m, name, total_mb })
            }
        }

        fn read(counter: PDH_HCOUNTER) -> Vec<(String, f64)> {
            unsafe {
                let (mut size, mut count) = (0u32, 0u32);
                let st = PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, std::ptr::null_mut());
                if st != PDH_MORE_DATA || size == 0 {
                    return vec![];
                }
                let mut buf = vec![0u8; size as usize];
                let items = buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
                if PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, items) != 0 {
                    return vec![];
                }
                (0..count as usize)
                    .map(|i| {
                        let it = &*items.add(i);
                        let mut n = 0;
                        while *it.szName.add(n) != 0 {
                            n += 1;
                        }
                        let name = String::from_utf16_lossy(std::slice::from_raw_parts(it.szName, n));
                        (name, it.FmtValue.Anonymous.doubleValue)
                    })
                    .collect()
            }
        }

        pub fn sample(&mut self) -> GpuInfo {
            unsafe {
                PdhCollectQueryData(self.query);
            }
            // Utilisation 3D : somme par carte (identifiée par son LUID), on garde la plus chargée.
            let mut per: std::collections::HashMap<String, f64> = Default::default();
            for (name, v) in Self::read(self.engine) {
                let luid = name.split("_phys").next().unwrap_or("").rsplit("luid_").next().unwrap_or("").to_string();
                *per.entry(luid).or_default() += v;
            }
            let util3d = per.values().cloned().fold(0.0, f64::max).min(100.0);
            let used = Self::read(self.memory).into_iter().map(|(_, v)| v).fold(0.0, f64::max) / 1_048_576.0;
            GpuInfo { name: self.name.clone(), util3d, vram_used_mb: used, vram_total_mb: self.total_mb }
        }
    }
}

#[derive(Serialize)]
struct Snapshot {
    cpu: f32,
    ram_used_mb: f64,
    ram_total_mb: f64,
    cores: usize,
    groups: Vec<Group>,
    game_mode: bool,
    gpu: Option<gpu::GpuInfo>,
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
    let windows_pids = win::window_pids();
    let full_pids = win::fullscreen_pids();
    let user_games: Vec<String> = load_json::<Config>("config.json").games.iter().map(|g| g.to_lowercase()).collect();
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
                has_window: false,
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
        if windows_pids.contains(&pid.as_u32()) {
            g.has_window = true;
        }
        if full_pids.contains(&pid.as_u32()) && !matches!(g.category.as_str(), "systeme" | "jeu") && name.to_lowercase() != "explorer.exe" {
            g.category = "jeu".into();
            g.label = "Jeu détecté (plein écran)".into();
        }
        g.pids.push(pid.as_u32());
        g.cpu += p.cpu_usage() / nc;
        g.mem_mb += p.memory() as f64 / 1_048_576.0;
    }
    for g in map.values_mut() {
        if user_games.contains(&g.name.to_lowercase()) {
            g.category = "jeu".into();
            g.label = "Jeu (ajouté par toi)".into();
        }
    }
    let mut v: Vec<Group> = map.into_values().collect();
    v.sort_by(|a, b| b.mem_mb.partial_cmp(&a.mem_mb).unwrap_or(std::cmp::Ordering::Equal));
    v
}

#[tauri::command]
async fn get_snapshot(state: tauri::State<'_, AppState>) -> Result<Snapshot, String> {
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
        gpu: state.gpu.lock().ok().and_then(|mut g| g.as_mut().map(|g| g.sample())),
    })
}

fn is_protected(name: &str) -> bool {
    let n = name.to_lowercase();
    lists::SYSTEM.contains(&n.as_str()) || lookup(lists::KEEP, &n).is_some()
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
async fn kill_group(state: tauri::State<'_, AppState>, name: String) -> Result<usize, String> {
    if is_protected(&name) {
        return Err("Processus protégé : le fermer pourrait faire planter Windows ou ton jeu.".into());
    }
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    refresh(&mut sys);
    Ok(kill_name(&sys, &name))
}

mod win {
    use std::collections::HashSet;
    use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindow, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible, GW_OWNER,
    };

    unsafe extern "system" fn collect(hwnd: HWND, lp: LPARAM) -> i32 {
        let set = &mut *(lp as *mut HashSet<u32>);
        if IsWindowVisible(hwnd) != 0 && GetWindow(hwnd, GW_OWNER).is_null() && GetWindowTextLengthW(hwnd) > 0 {
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);
            set.insert(pid);
        }
        1
    }

    /// PID des programmes qui ont une fenêtre principale visible.
    pub fn window_pids() -> HashSet<u32> {
        let mut set: HashSet<u32> = HashSet::new();
        unsafe {
            EnumWindows(Some(collect), &mut set as *mut _ as LPARAM);
        }
        set
    }

    unsafe extern "system" fn collect_full(hwnd: HWND, lp: LPARAM) -> i32 {
        use windows_sys::Win32::Foundation::RECT;
        use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetDesktopWindow, GetWindowRect};
        let set = &mut *(lp as *mut HashSet<u32>);
        if IsWindowVisible(hwnd) == 0 || hwnd == GetShellWindow() || hwnd == GetDesktopWindow() {
            return 1;
        }
        let mut r: RECT = std::mem::zeroed();
        if GetWindowRect(hwnd, &mut r) == 0 {
            return 1;
        }
        let mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(mon, &mut mi) == 0 {
            return 1;
        }
        let m = mi.rcMonitor;
        // Fenêtre qui couvre tout l'écran : plein écran ou fenêtré sans bordure.
        if r.left <= m.left && r.top <= m.top && r.right >= m.right && r.bottom >= m.bottom {
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);
            set.insert(pid);
        }
        1
    }

    /// PID des programmes affichés en plein écran (très probablement un jeu).
    pub fn fullscreen_pids() -> HashSet<u32> {
        let mut set: HashSet<u32> = HashSet::new();
        unsafe {
            EnumWindows(Some(collect_full), &mut set as *mut _ as LPARAM);
        }
        set
    }

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

#[derive(Serialize)]
struct KillReport {
    killed: Vec<String>,
    failed: Vec<String>,
    ram_freed_mb: f64,
}

/// Ferme plusieurs programmes d'un coup (après confirmation dans l'interface).
#[tauri::command]
async fn kill_many(state: tauri::State<'_, AppState>, names: Vec<String>) -> Result<KillReport, String> {
    let mut sys = state.sys.lock().map_err(|e| e.to_string())?;
    refresh(&mut sys);
    let before = sys.available_memory();
    let (mut killed, mut failed) = (vec![], vec![]);
    for n in names {
        if kill_name(&sys, &n) > 0 { killed.push(n) } else { failed.push(n) }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    sys.refresh_memory();
    let ram_freed_mb = (sys.available_memory() as f64 - before as f64).max(0.0) / 1_048_576.0;
    Ok(KillReport { killed, failed, ram_freed_mb })
}

#[tauri::command]
fn show_window(app: AppHandle) {
    show_main(&app);
}

#[tauri::command]
async fn set_priority(state: tauri::State<'_, AppState>, name: String, level: String) -> Result<usize, String> {
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
async fn free_ram(state: tauri::State<'_, AppState>) -> Result<f64, String> {
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
    /// Vidage automatique de la RAM tant que le mode jeu est actif.
    #[serde(default)]
    auto_trim: bool,
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
    #[serde(default)]
    game_on_start: bool,
    /// Programmes que l'utilisateur a marqués comme jeux.
    #[serde(default)]
    games: Vec<String>,
    /// Overlay de 5 s quand un jeu démarre (activé par défaut).
    #[serde(default)]
    overlay: Option<bool>,
}

#[tauri::command]
fn set_overlay(enabled: bool) {
    let mut cfg: Config = load_json("config.json");
    cfg.overlay = Some(enabled);
    save_json("config.json", &cfg);
}

// ---------------------------------------------------------------- overlay « jeu détecté »

fn url_encode(v: &str) -> String {
    v.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Petite fenêtre en haut à gauche, au premier plan, qui ne prend pas le focus du jeu.
fn show_overlay(app: &AppHandle, game: &str, exe: &str) {
    open_overlay(app, &format!("overlay.html?game={}&exe={}", url_encode(game), url_encode(exe)), 300.0, 90.0);
}

#[tauri::command]
fn notify_update(app: AppHandle, version: String) {
    open_overlay(&app, &format!("overlay.html?kind=update&v={}", url_encode(&version)), 360.0, 104.0);
}

fn open_overlay(app: &AppHandle, page: &str, w: f64, h: f64) {
    use tauri::{LogicalPosition, WebviewUrl, WebviewWindowBuilder};
    if let Some(win) = app.get_webview_window("overlay") {
        let _ = win.close();
    }
    let (mut x, mut y) = (24.0, 24.0);
    if let Ok(Some(m)) = app.primary_monitor() {
        let sf = m.scale_factor();
        let pos = m.position().to_logical::<f64>(sf);
        x = pos.x + 24.0;
        y = pos.y + 24.0;
    }
    let url = WebviewUrl::App(page.into());
    let _ = WebviewWindowBuilder::new(app, "overlay", url)
        .title("Perf Saver")
        .inner_size(w, h)
        .position(x, y)
        .decorations(false)
        .transparent(true)
        .shadow(false)
        .resizable(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .focused(false)
        .build()
        .map(|win| {
            let _ = win.set_position(LogicalPosition::new(x, y));
        });
}

#[tauri::command]
fn overlay_action(app: AppHandle, action: String) {
    if let Some(w) = app.get_webview_window("overlay") {
        let _ = w.close();
    }
    match action.as_str() {
        "open" => show_main(&app),
        "game" => {
            show_main(&app);
            let _ = app.emit("tray-game", ());
        }
        "update" => {
            show_main(&app);
            let _ = app.emit("do-update", ());
        }
        _ => {}
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// Icône de l'exécutable du jeu, extraite via .NET (System.Drawing) et mise en cache
/// sur le disque. Renvoie une image encodée en base64 (data URI) ou rien si indisponible.
#[tauri::command]
async fn game_icon(exe: String) -> Option<String> {
    if exe.trim().is_empty() {
        return None;
    }
    use sha2::{Digest, Sha256};
    let key: String = Sha256::digest(exe.to_lowercase().as_bytes()).iter().take(12).map(|b| format!("{b:02x}")).collect();
    let dir = data_dir().join("icons");
    let _ = std::fs::create_dir_all(&dir);
    let png_path = dir.join(format!("{key}.png"));
    if !png_path.exists() {
        let script = "& { param($a, $b) \
            try { \
                Add-Type -AssemblyName System.Drawing; \
                $i = [System.Drawing.Icon]::ExtractAssociatedIcon($a); \
                if ($i) { $i.ToBitmap().Save($b, [System.Drawing.Imaging.ImageFormat]::Png) } \
            } catch {} \
        }";
        let png_arg = png_path.to_string_lossy().to_string();
        let _ = tauri::async_runtime::spawn_blocking(move || {
            Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script, exe.as_str(), png_arg.as_str()])
                .creation_flags(NO_WINDOW)
                .output()
        })
        .await;
    }
    let bytes = std::fs::read(&png_path).ok().filter(|b| !b.is_empty())?;
    Some(format!("data:image/png;base64,{}", base64_encode(&bytes)))
}

/// Nom lisible pour les jeux connus (sinon le nom de l'exécutable sans « .exe »).
fn pretty_game(exe: &str) -> String {
    let n = exe.to_lowercase();
    let known = [
        ("robloxplayerbeta", "Roblox"), ("windows10universal", "Roblox"), ("robloxstudio", "Roblox Studio"),
        ("x-plane", "X-Plane"), ("flightsimulator2024", "Flight Simulator 2024"), ("flightsimulator", "Flight Simulator"),
        ("javaw", "Minecraft"), ("minecraft", "Minecraft"), ("fortniteclient", "Fortnite"), ("valorant", "Valorant"),
        ("league of legends", "League of Legends"), ("cs2", "Counter-Strike 2"), ("r5apex", "Apex Legends"),
        ("gta5", "GTA V"), ("rocketleague", "Rocket League"), ("tslgame", "PUBG"), ("rainbowsix", "Rainbow Six Siege"),
        ("overwatch", "Overwatch 2"), ("genshinimpact", "Genshin Impact"), ("marvel-win64", "Marvel Rivals"),
    ];
    for (k, v) in known {
        if n.starts_with(k) {
            return v.to_string();
        }
    }
    exe.rsplit_once('.').map(|(a, _)| a).unwrap_or(exe).to_string()
}

/// Surveille le lancement des jeux (toutes les 5 s) et affiche l'overlay
/// quand un nouveau jeu apparaît et que le mode jeu n'est pas actif.
fn game_watcher(app: AppHandle) {
    std::thread::spawn(move || {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut first = true;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(if first { 3 } else { 5 }));
            let games: Vec<(String, String)> = {
                let state = app.state::<AppState>();
                let Ok(mut sys) = state.sys.lock() else { continue };
                refresh(&mut sys);
                build_groups(&sys).into_iter().filter(|g| g.category == "jeu").map(|g| (g.name, g.exe)).collect()
            };
            let cfg: Config = load_json("config.json");
            let st: GameState = load_json("state.json");
            let enabled = cfg.overlay != Some(false) && cfg.terms_accepted.is_some();
            for (g, exe) in &games {
                let k = g.to_lowercase();
                if seen.insert(k) && !first && enabled && !st.active {
                    let label = pretty_game(g);
                    let a = app.clone();
                    let exe = exe.clone();
                    let _ = app.run_on_main_thread(move || show_overlay(&a, &label, &exe));
                }
            }
            seen.retain(|k| games.iter().any(|(g, _)| g.to_lowercase() == *k));
            first = false;
        }
    });
}

#[tauri::command]
fn set_game(name: String, is_game: bool) {
    let mut cfg: Config = load_json("config.json");
    cfg.games.retain(|g| !g.eq_ignore_ascii_case(&name));
    if is_game {
        cfg.games.push(name);
    }
    save_json("config.json", &cfg);
}

#[tauri::command]
fn set_game_on_start(enabled: bool) {
    let mut cfg: Config = load_json("config.json");
    cfg.game_on_start = enabled;
    save_json("config.json", &cfg);
}

/// Seuil d'utilisation de la mémoire au-delà duquel le mode jeu vide la RAM,
/// et délai minimal entre deux vidages (évite de ralentir le PC en boucle).
const RAM_TRIM_THRESHOLD: f64 = 0.70;
const RAM_TRIM_MIN_GAP: std::time::Duration = std::time::Duration::from_secs(120);

fn ram_guard(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last: Option<std::time::Instant> = None;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            let st: GameState = load_json("state.json");
            if !st.active || !st.auto_trim {
                continue;
            }
            if last.map(|t| t.elapsed() < RAM_TRIM_MIN_GAP).unwrap_or(false) {
                continue;
            }
            let state = app.state::<AppState>();
            let Ok(mut sys) = state.sys.lock() else { continue };
            sys.refresh_memory();
            let total = sys.total_memory() as f64;
            if total <= 0.0 {
                continue;
            }
            let used = (total - sys.available_memory() as f64) / total;
            if used < RAM_TRIM_THRESHOLD {
                continue;
            }
            let freed = trim_all(&mut sys);
            drop(sys);
            last = Some(std::time::Instant::now());
            let _ = app.emit("ram-auto", freed);
        }
    });
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
    /// false pour « Optimisation max » : ne remplace pas la sélection enregistrée.
    #[serde(default)]
    save: Option<bool>,
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
    if req.save != Some(false) {
        cfg.kill = req.kill.clone();
        cfg.services = req.services.clone();
        cfg.options = Some(req.options.clone());
    }

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
    st.auto_trim = req.options.trim;
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

// ---------------------------------------------------------------- instance unique + droits admin

mod elevation {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn is_elevated() -> bool {
        unsafe {
            let mut t: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) == 0 {
                return false;
            }
            let mut e: TOKEN_ELEVATION = std::mem::zeroed();
            let mut len = 0u32;
            let ok = GetTokenInformation(
                t,
                TokenElevation,
                &mut e as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            ) != 0;
            CloseHandle(t);
            ok && e.TokenIsElevated != 0
        }
    }

    /// Relance l'application avec les droits administrateur (une seule demande UAC).
    pub fn relaunch_elevated(args: &str) -> bool {
        let Ok(exe) = std::env::current_exe() else { return false };
        let file = wide(&exe.to_string_lossy());
        let verb = wide("runas");
        let params = wide(args);
        unsafe {
            let mut i: SHELLEXECUTEINFOW = std::mem::zeroed();
            i.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            i.lpVerb = verb.as_ptr();
            i.lpFile = file.as_ptr();
            i.lpParameters = params.as_ptr();
            i.nShow = SW_SHOWNORMAL as i32;
            ShellExecuteExW(&mut i) != 0
        }
    }

    /// Chemin de l'exécutable d'un processus (fonctionne même s'il est élevé).
    pub fn process_path(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
            CloseHandle(h);
            ok.then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }
}

/// Une instance de Perf Saver tourne-t-elle déjà ? (fichier PID + vérification du processus)
fn running_instance() -> bool {
    let Ok(txt) = std::fs::read_to_string(data_dir().join("instance.pid")) else { return false };
    let Ok(pid) = txt.trim().parse::<u32>() else { return false };
    if pid == std::process::id() {
        return false;
    }
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    elevation::process_path(pid)
        .map(|p| p.to_lowercase().ends_with(&me))
        .unwrap_or(false)
}

/// L'instance déjà ouverte surveille ce fichier pour afficher sa fenêtre :
/// un simple fichier passe entre un processus normal et un processus administrateur.
fn signal_watcher(app: AppHandle) {
    std::thread::spawn(move || {
        let sig = data_dir().join("show.signal");
        loop {
            std::thread::sleep(std::time::Duration::from_millis(400));
            if sig.exists() {
                let _ = std::fs::remove_file(&sig);
                let a = app.clone();
                let _ = app.run_on_main_thread(move || show_main(&a));
            }
        }
    });
}

fn main() {
    // 1. Déjà ouvert : on affiche la fenêtre existante, sans demande administrateur.
    if running_instance() {
        let _ = std::fs::write(data_dir().join("show.signal"), b"1");
        return;
    }
    // 2. Premier lancement sans droits : une seule demande UAC, puis cette copie se ferme.
    if !elevation::is_elevated() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if elevation::relaunch_elevated(&args.join(" ")) {
            return;
        }
        // Demande refusée : l'app s'ouvre quand même, avec des fonctions limitées.
    }
    let _ = std::fs::write(data_dir().join("instance.pid"), std::process::id().to_string());
    let _ = std::fs::remove_file(data_dir().join("show.signal"));

    let mut sys = System::new();
    refresh(&mut sys);
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .manage(AppState { sys: Mutex::new(sys), gpu: Mutex::new(gpu::Gpu::new()), tray_game: Mutex::new(None) })
        .setup(|app| {
            setup_tray(app)?;
            ram_guard(app.handle().clone());
            game_watcher(app.handle().clone());
            signal_watcher(app.handle().clone());
            let hidden = std::env::args().any(|a| a == "--tray");
            if !hidden {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|w, ev| {
            // Fermer la fenêtre = réduire dans la zone de notification
            if let WindowEvent::CloseRequested { api, .. } = ev {
                if w.label() == "main" {
                    api.prevent_close();
                    let _ = w.hide();
                }
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
            set_auto_update,
            set_game_on_start,
            set_game,
            set_overlay,
            overlay_action,
            notify_update,
            game_icon,
            kill_many,
            show_window
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Perf Saver");
}
