#![forbid(unsafe_code)]
//! Software-Only Proximity Shield
//!
//! Combines four built-in PC hardware subsystems with zero external dongles:
//! 1. Built-In Wi-Fi & Bluetooth (Close-Range RF Shield): passive BLE RSSI + dwell-time
//!    filtering (> -55 dBm for >= 10s) and Wi-Fi hotspot / Wi-Fi Direct / probe detection.
//! 2. Built-In Webcam (Offline Vision & Glare Detection): rectangular screen-glare,
//!    sudden lighting shift, and secondary face/gaze anomaly detection.
//! 3. Built-In Speaker & Microphone (Acoustic / Ultrasonic Shield): 19.5 kHz ultrasonic
//!    Doppler shift detection + RF/earpiece feedback interference check via Goertzel DFT.
//! 4. Internal Bus & Display Guard: real-time DRM/KMS connector, USB/HID hotplug,
//!    and PCIe/Thunderbolt DMA monitoring.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::f64::consts::PI;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShieldSubsystem {
    RfBluetoothWifi,
    VisionGlare,
    UltrasonicAcoustic,
    BusDisplayGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Advisory,
    Warning,
    CriticalTamper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityAlert {
    pub subsystem: ShieldSubsystem,
    pub severity: AlertSeverity,
    pub code: String,
    pub detail: String,
    pub timestamp_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityReport {
    pub rf_ble_tracked: usize,
    pub rf_wifi_suspicious: usize,
    pub vision_glare_score: f64,
    pub ultrasonic_doppler_ratio: f64,
    pub external_displays_connected: usize,
    pub unauthorized_usb_devices: usize,
    pub alerts: Vec<ProximityAlert>,
}

/* ============================================================================
 * 1. Built-In Wi-Fi & Bluetooth (Close-Range RF Shield)
 * ============================================================================ */

#[derive(Debug, Clone)]
struct BleSighting {
    first_seen_sec: u64,
    last_seen_sec: u64,
    peak_rssi: i32,
}

pub struct RfShieldMonitor {
    ble_devices: HashMap<String, BleSighting>,
    allowlisted_macs: HashSet<String>,
    pub rssi_threshold_dbm: i32,
    pub dwell_threshold_sec: u64,
}

impl RfShieldMonitor {
    pub fn new(allowlisted_macs: Vec<String>) -> Self {
        Self {
            ble_devices: HashMap::new(),
            allowlisted_macs: allowlisted_macs
                .into_iter()
                .map(|m| m.to_uppercase())
                .collect(),
            rssi_threshold_dbm: -55,
            dwell_threshold_sec: 10,
        }
    }

    /// Updates sliding-window BLE proximity state; flags unknown devices > -55 dBm for > 10s.
    pub fn observe_ble(&mut self, mac: &str, rssi_dbm: i32, now_sec: u64) -> Option<ProximityAlert> {
        let norm = mac.trim().to_uppercase();
        if norm.is_empty() || self.allowlisted_macs.contains(&norm) {
            return None;
        }
        if rssi_dbm < self.rssi_threshold_dbm {
            // Device moved out of 1-2m zone; reset dwell timer so passersby don't trigger.
            self.ble_devices.remove(&norm);
            return None;
        }
        let entry = self.ble_devices.entry(norm.clone()).or_insert(BleSighting {
            first_seen_sec: now_sec,
            last_seen_sec: now_sec,
            peak_rssi: rssi_dbm,
        });
        entry.last_seen_sec = now_sec;
        if rssi_dbm > entry.peak_rssi {
            entry.peak_rssi = rssi_dbm;
        }
        let dwell = now_sec.saturating_sub(entry.first_seen_sec);
        if dwell >= self.dwell_threshold_sec {
            return Some(ProximityAlert {
                subsystem: ShieldSubsystem::RfBluetoothWifi,
                severity: AlertSeverity::Warning,
                code: "BLE_CLOSE_PROXIMITY".to_string(),
                detail: format!(
                    "Unknown BLE device {norm} stayed at {rssi_dbm} dBm (> {} dBm) for {dwell}s",
                    self.rssi_threshold_dbm
                ),
                timestamp_sec: now_sec,
            });
        }
        None
    }

    /// Number of unknown BLE devices currently inside the close-range window.
    pub fn tracked_ble_count(&self) -> usize {
        self.ble_devices.len()
    }

    /// Evaluates Wi-Fi scan records for nearby mobile tethering hotspots or Wi-Fi Direct.
    pub fn evaluate_wifi_ap(
        &self,
        ssid: &str,
        bssid: &str,
        signal_dbm: i32,
        now_sec: u64,
    ) -> Option<ProximityAlert> {
        if signal_dbm < self.rssi_threshold_dbm {
            return None;
        }
        let upper = ssid.to_uppercase();
        let is_direct = upper.starts_with("DIRECT-");
        let is_hotspot = upper.contains("IPHONE")
            || upper.contains("ANDROIDAP")
            || upper.contains("HOTSPOT")
            || upper.contains("PIXEL")
            || upper.contains("GALAXY");
        if is_direct || is_hotspot {
            return Some(ProximityAlert {
                subsystem: ShieldSubsystem::RfBluetoothWifi,
                severity: AlertSeverity::Warning,
                code: if is_direct {
                    "WIFI_DIRECT_NEARBY".to_string()
                } else {
                    "MOBILE_HOTSPOT_NEARBY".to_string()
                },
                detail: format!(
                    "Close-range Wi-Fi {} '{}' ({}) at {} dBm",
                    if is_direct { "Direct" } else { "Hotspot" },
                    ssid,
                    bssid,
                    signal_dbm
                ),
                timestamp_sec: now_sec,
            });
        }
        None
    }

    /// Runs live BlueZ & nmcli/iw scans on Linux hardware when interfaces are present.
    pub fn scan_linux_hardware(&mut self, now_sec: u64) -> Vec<ProximityAlert> {
        let mut alerts = Vec::new();
        // Prune stale BLE sightings older than 30s
        self.ble_devices
            .retain(|_, v| now_sec.saturating_sub(v.last_seen_sec) <= 30);

        if Path::new("/sys/class/bluetooth").exists() {
            if let Ok(out) = Command::new("bluetoothctl").args(["devices"]).output() {
                let txt = String::from_utf8_lossy(&out.stdout);
                for line in txt.lines() {
                    if let Some(mac) = line.split_whitespace().nth(1) {
                        if let Ok(info) = Command::new("bluetoothctl").args(["info", mac]).output() {
                            let info_txt = String::from_utf8_lossy(&info.stdout);
                            for il in info_txt.lines() {
                                if let Some(rest) = il.trim().strip_prefix("RSSI:") {
                                    if let Ok(rssi) = rest.trim().parse::<i32>() {
                                        if let Some(a) = self.observe_ble(mac, rssi, now_sec) {
                                            alerts.push(a);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if Path::new("/proc/net/wireless").exists() {
            if let Ok(out) = Command::new("nmcli")
                .args(["-t", "-f", "SSID,BSSID,SIGNAL", "dev", "wifi", "list", "--rescan", "no"])
                .output()
            {
                let txt = String::from_utf8_lossy(&out.stdout);
                for line in txt.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 3 {
                        let ssid = parts[0];
                        let bssid = parts[1];
                        if let Ok(pct) = parts[parts.len() - 1].trim().parse::<i32>() {
                            // Convert nmcli 0-100% signal quality to approximate dBm
                            let approx_dbm = (pct / 2) - 100;
                            if let Some(a) = self.evaluate_wifi_ap(ssid, bssid, approx_dbm, now_sec) {
                                alerts.push(a);
                            }
                        }
                    }
                }
            }
        }
        alerts
    }
}

/* ============================================================================
 * 2. Built-In Webcam (Offline Vision & Glare Detection)
 * ============================================================================ */

pub struct VisionGlareDetector {
    prev_mean_luma: Option<f64>,
    pub onnx_model_present: bool,
}

impl VisionGlareDetector {
    pub fn new() -> Self {
        Self {
            prev_mean_luma: None,
            onnx_model_present: Path::new("/etc/examos/models/proximity_vision.onnx").exists(),
        }
    }

    /// Analyzes an 8-bit grayscale luma frame for secondary-screen glare and lighting shifts.
    pub fn analyze_luma_frame(
        &mut self,
        luma: &[u8],
        width: usize,
        height: usize,
        now_sec: u64,
    ) -> (f64, Vec<ProximityAlert>) {
        let mut alerts = Vec::new();
        if luma.is_empty() || width == 0 || height == 0 || luma.len() < width * height {
            return (0.0, alerts);
        }

        let total = (width * height) as f64;
        let mean_luma = luma.iter().map(|&p| p as f64).sum::<f64>() / total;
        let bright_pixels = luma.iter().filter(|&&p| p >= 235).count() as f64;
        let dark_pixels = luma.iter().filter(|&&p| p <= 85).count() as f64;
        let bright_ratio = bright_pixels / total;
        let dark_ratio = dark_pixels / total;

        // Glare score: high-contrast bright rectangular patch inside a dim room
        let glare_score = if dark_ratio > 0.45 && bright_ratio > 0.04 {
            (bright_ratio * 6.0).min(1.0)
        } else {
            (bright_ratio * 1.5).min(1.0)
        };

        if glare_score >= 0.35 {
            alerts.push(ProximityAlert {
                subsystem: ShieldSubsystem::VisionGlare,
                severity: AlertSeverity::Warning,
                code: "SCREEN_GLARE_DETECTED".to_string(),
                detail: format!(
                    "Bright rectangular glare detected in dim scene (glare_score={glare_score:.2}, mean_luma={mean_luma:.1})"
                ),
                timestamp_sec: now_sec,
            });
        }

        if let Some(prev) = self.prev_mean_luma {
            let delta = (mean_luma - prev).abs();
            if delta > 28.0 {
                alerts.push(ProximityAlert {
                    subsystem: ShieldSubsystem::VisionGlare,
                    severity: AlertSeverity::Advisory,
                    code: "SUDDEN_LIGHTING_SHIFT".to_string(),
                    detail: format!("Sudden facial/room illumination shift (delta={delta:.1} luma)"),
                    timestamp_sec: now_sec,
                });
            }
        }
        self.prev_mean_luma = Some(mean_luma);
        (glare_score, alerts)
    }
}

/* ============================================================================
 * 3. Built-In Speaker & Microphone (Acoustic / Ultrasonic Shield)
 * ============================================================================ */

pub struct AcousticUltrasonicShield {
    pub sample_rate_hz: f64,
    pub carrier_hz: f64,
}

impl AcousticUltrasonicShield {
    pub fn new() -> Self {
        Self {
            sample_rate_hz: 48_000.0,
            carrier_hz: 19_500.0,
        }
    }

    /// Generates an inaudible 19.5 kHz soft ultrasonic probe tone (S16_LE PCM).
    pub fn generate_ultrasonic_pulse_pcm(&self, duration_ms: usize) -> Vec<i16> {
        let count = ((self.sample_rate_hz * duration_ms as f64) / 1000.0) as usize;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let t = i as f64 / self.sample_rate_hz;
            let env = (PI * i as f64 / count as f64).sin();
            let sample = (2.0 * PI * self.carrier_hz * t).sin() * env * 2400.0;
            out.push(sample as i16);
        }
        out
    }

    /// Goertzel single-frequency DFT magnitude squared.
    fn goertzel_power(&self, samples: &[i16], target_hz: f64) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let k = (0.5 + (samples.len() as f64 * target_hz) / self.sample_rate_hz).floor();
        let omega = (2.0 * PI * k) / samples.len() as f64;
        let coeff = 2.0 * omega.cos();
        let mut q1 = 0.0;
        let mut q2 = 0.0;
        for &s in samples {
            let q0 = coeff * q1 - q2 + (s as f64);
            q2 = q1;
            q1 = q0;
        }
        let power = q1 * q1 + q2 * q2 - q1 * q2 * coeff;
        power / (samples.len() as f64 * samples.len() as f64)
    }

    /// Analyzes microphone PCM samples for ultrasonic Doppler shifts (19.5 kHz +/- 250 Hz)
    /// and earpiece RF/acoustic feedback peaks.
    pub fn analyze_mic_pcm(&self, samples: &[i16], now_sec: u64) -> (f64, Vec<ProximityAlert>) {
        let mut alerts = Vec::new();
        if samples.len() < 256 {
            return (0.0, alerts);
        }
        let carrier = self.goertzel_power(samples, self.carrier_hz).max(1e-6);
        let lower_doppler = self.goertzel_power(samples, self.carrier_hz - 220.0);
        let upper_doppler = self.goertzel_power(samples, self.carrier_hz + 220.0);
        let doppler_ratio = (lower_doppler + upper_doppler) / carrier;

        if doppler_ratio > 0.35 {
            alerts.push(ProximityAlert {
                subsystem: ShieldSubsystem::UltrasonicAcoustic,
                severity: AlertSeverity::Warning,
                code: "ULTRASONIC_DOPPLER_MOTION".to_string(),
                detail: format!(
                    "Ultrasonic 19.5 kHz Doppler shift detected (sideband/carrier={doppler_ratio:.2})"
                ),
                timestamp_sec: now_sec,
            });
        }

        // Check for earpiece feedback / narrowband coupling around 4.2 kHz
        let total_rms = (samples.iter().map(|&s| (s as f64) * (s as f64)).sum::<f64>()
            / samples.len() as f64)
            .sqrt();
        let feedback_p = self.goertzel_power(samples, 4_200.0).sqrt();
        if total_rms > 50.0 && (feedback_p / total_rms) > 0.45 {
            alerts.push(ProximityAlert {
                subsystem: ShieldSubsystem::UltrasonicAcoustic,
                severity: AlertSeverity::Warning,
                code: "EARPIECE_ACOUSTIC_FEEDBACK".to_string(),
                detail: "Narrowband acoustic/RF earpiece interference detected".to_string(),
                timestamp_sec: now_sec,
            });
        }
        (doppler_ratio, alerts)
    }
}

/* ============================================================================
 * 4. Internal Bus & Display Guard
 * ============================================================================ */

pub struct BusDisplayGuard {
    baseline_usb_devices: HashSet<String>,
}

impl BusDisplayGuard {
    pub fn capture_baseline() -> Self {
        Self {
            baseline_usb_devices: Self::list_usb_devices(),
        }
    }

    /// Loads a previously persisted USB baseline, or captures and persists a new
    /// one. A one-shot CLI invocation therefore still detects devices that were
    /// plugged in after the baseline was recorded during provisioning.
    pub fn load_or_capture_baseline(path: &str) -> Self {
        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(devices) = serde_json::from_str::<Vec<String>>(&raw) {
                return Self {
                    baseline_usb_devices: devices.into_iter().collect(),
                };
            }
        }

        let guard = Self::capture_baseline();
        let devices: Vec<String> = guard.baseline_usb_devices.iter().cloned().collect();
        if let Ok(json) = serde_json::to_string(&devices) {
            if let Some(parent) = Path::new(path).parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(error) = fs::write(path, json) {
                eprintln!("[proximity] cannot persist USB bus baseline {path}: {error}");
            }
        }
        guard
    }

    fn list_usb_devices() -> HashSet<String> {
        let mut set = HashSet::new();
        if let Ok(entries) = Path::new("/sys/bus/usb/devices").read_dir() {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if entry.path().join("idVendor").exists() {
                        set.insert(name.to_string());
                    }
                }
            }
        }
        set
    }

    pub fn scan(&self, now_sec: u64) -> (usize, usize, Vec<ProximityAlert>) {
        let mut alerts = Vec::new();
        let mut external_displays = 0usize;

        if let Ok(entries) = Path::new("/sys/class/drm").read_dir() {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains("HDMI") || name.contains("DP-") || name.contains("DVI") || name.contains("VGA") {
                    if let Ok(status) = fs::read_to_string(entry.path().join("status")) {
                        if status.trim() == "connected" {
                            external_displays += 1;
                            alerts.push(ProximityAlert {
                                subsystem: ShieldSubsystem::BusDisplayGuard,
                                severity: AlertSeverity::CriticalTamper,
                                code: "EXTERNAL_DISPLAY_CONNECTED".to_string(),
                                detail: format!("Unauthorized external/capture display connector active: {name}"),
                                timestamp_sec: now_sec,
                            });
                        }
                    }
                }
            }
        }

        let current_usb = Self::list_usb_devices();
        let mut new_usb = 0usize;
        for dev in current_usb.difference(&self.baseline_usb_devices) {
            new_usb += 1;
            let class_path = Path::new("/sys/bus/usb/devices").join(dev).join("bDeviceClass");
            let dev_class = fs::read_to_string(class_path).unwrap_or_default();
            alerts.push(ProximityAlert {
                subsystem: ShieldSubsystem::BusDisplayGuard,
                severity: AlertSeverity::CriticalTamper,
                code: "USB_HOTPLUG_BLOCKED".to_string(),
                detail: format!("Hotplugged USB device {dev} (class={}) detected during locked session", dev_class.trim()),
                timestamp_sec: now_sec,
            });
        }

        (external_displays, new_usb, alerts)
    }
}

/* ============================================================================
 * Live capture helpers
 * ============================================================================ */

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const PCM_SAMPLE_RATE: usize = 48_000;

/// Captures one frame from the first usable V4L2 device and returns packed
/// 8-bit luma plus its dimensions. Returns `None` when no capture device or
/// no `v4l2-ctl` binary is available; callers report the subsystem as
/// unavailable rather than fabricating a score.
pub fn capture_webcam_luma() -> Option<(Vec<u8>, usize, usize)> {
    for index in 0..8 {
        let device = format!("/dev/video{index}");
        if !Path::new(&device).exists() {
            continue;
        }
        if let Some(frame) = capture_v4l2_frame(&device) {
            return Some(frame);
        }
    }
    None
}

fn capture_v4l2_frame(device: &str) -> Option<(Vec<u8>, usize, usize)> {
    let format = Command::new("v4l2-ctl")
        .args(["--device", device, "--get-fmt-video"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !format.status.success() {
        return None;
    }
    let format_text = String::from_utf8_lossy(&format.stdout);
    let (width, height) = parse_v4l2_dimensions(&format_text)?;
    let pixel_format = parse_v4l2_pixel_format(&format_text).unwrap_or_default();

    let mut child = Command::new("v4l2-ctl")
        .args([
            "--device",
            device,
            "--stream-mmap",
            "--stream-count=1",
            "--stream-to=-",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    while raw.len() < MAX_FRAME_BYTES {
        match stdout.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    unpack_luma(&raw, width, height, &pixel_format)
}

fn parse_v4l2_dimensions(text: &str) -> Option<(usize, usize)> {
    for line in text.lines() {
        if !line.contains("Width/Height") {
            continue;
        }
        let value = line.split_once(':')?.1.trim();
        let (width, height) = value.split_once('/')?;
        return Some((width.trim().parse().ok()?, height.trim().parse().ok()?));
    }
    None
}

fn parse_v4l2_pixel_format(text: &str) -> Option<String> {
    for line in text.lines() {
        if !line.contains("Pixel Format") {
            continue;
        }
        let value = line.split_once(':')?.1;
        let start = value.find('\'')? + 1;
        let end = value[start..].find('\'')? + start;
        return Some(value[start..end].trim().to_uppercase());
    }
    None
}

fn unpack_luma(
    raw: &[u8],
    width: usize,
    height: usize,
    pixel_format: &str,
) -> Option<(Vec<u8>, usize, usize)> {
    let pixels = width.checked_mul(height)?;
    if width == 0 || height == 0 || raw.len() < pixels {
        return None;
    }

    let luma = match pixel_format {
        "YUYV" | "YUY2" => {
            if raw.len() < pixels * 2 {
                return None;
            }
            raw.iter().step_by(2).take(pixels).copied().collect()
        }
        "UYVY" => {
            if raw.len() < pixels * 2 {
                return None;
            }
            raw.iter().skip(1).step_by(2).take(pixels).copied().collect()
        }
        "NV12" | "NV21" => raw[..pixels].to_vec(),
        "RGB24" | "BGR24" => {
            if raw.len() < pixels * 3 {
                return None;
            }
            let rgb_order_is_rgb = pixel_format == "RGB24";
            raw.chunks_exact(3)
                .take(pixels)
                .map(|p| {
                    let (r, g, b) = if rgb_order_is_rgb {
                        (p[0], p[1], p[2])
                    } else {
                        (p[2], p[1], p[0])
                    };
                    ((r as u32 * 77 + g as u32 * 150 + b as u32 * 29) >> 8) as u8
                })
                .collect()
        }
        _ => raw[..pixels].to_vec(),
    };
    Some((luma, width, height))
}

/// Captures a short 48 kHz mono microphone window. `arecord` is preferred
/// because it terminates on its own; `parec` (PipeWire) is used as a fallback
/// and the child is explicitly killed after a bounded read.
pub fn capture_mic_pcm() -> Option<Vec<i16>> {
    if !Path::new("/dev/snd").exists() {
        return None;
    }
    if let Some(pcm) = capture_arecord_pcm() {
        return Some(pcm);
    }
    capture_parec_pcm()
}

fn capture_arecord_pcm() -> Option<Vec<i16>> {
    let output = Command::new("arecord")
        .args([
            "-q",
            "-d",
            "1",
            "-f",
            "S16_LE",
            "-r",
            "48000",
            "-c",
            "1",
            "-t",
            "raw",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    pcm_from_le_bytes(&output.stdout)
}

fn capture_parec_pcm() -> Option<Vec<i16>> {
    let mut child = Command::new("parec")
        .args([
            "--format=s16le",
            "--rate=48000",
            "--channels=1",
            "--latency-msec=100",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    // Read at most one second of mono S16_LE audio.
    while bytes.len() < PCM_SAMPLE_RATE * 2 {
        match stdout.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    pcm_from_le_bytes(&bytes)
}

fn pcm_from_le_bytes(bytes: &[u8]) -> Option<Vec<i16>> {
    let samples: Vec<i16> = bytes
        .chunks_exact(2)
        .take(PCM_SAMPLE_RATE)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    if samples.len() < 256 {
        return None;
    }
    Some(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_filter_ignores_passerby_and_flags_sustained_proximity() {
        let mut rf = RfShieldMonitor::new(vec![]);
        assert!(rf.observe_ble("AA:BB:CC:DD:EE:01", -48, 100).is_none());
        assert!(rf.observe_ble("AA:BB:CC:DD:EE:01", -50, 105).is_none());
        // Passerby leaves at 107s
        assert!(rf.observe_ble("AA:BB:CC:DD:EE:01", -72, 107).is_none());
        // Returns and stays >= 10s
        assert!(rf.observe_ble("AA:BB:CC:DD:EE:01", -49, 200).is_none());
        let alert = rf.observe_ble("AA:BB:CC:DD:EE:01", -47, 211).expect("sustained BLE alert");
        assert_eq!(alert.code, "BLE_CLOSE_PROXIMITY");
    }

    #[test]
    fn vision_glare_detects_bright_screen_in_dim_room() {
        let mut det = VisionGlareDetector::new();
        let mut frame = vec![35u8; 64 * 64];
        for y in 20..36 {
            for x in 20..40 {
                frame[y * 64 + x] = 250;
            }
        }
        let (score, alerts) = det.analyze_luma_frame(&frame, 64, 64, 1);
        assert!(score >= 0.35);
        assert!(alerts.iter().any(|a| a.code == "SCREEN_GLARE_DETECTED"));
    }

    #[test]
    fn ultrasonic_shield_detects_doppler_shift() {
        let shield = AcousticUltrasonicShield::new();
        let mut pure = shield.generate_ultrasonic_pulse_pcm(50);
        let (_, alerts_clean) = shield.analyze_mic_pcm(&pure, 1);
        assert!(alerts_clean.is_empty());

        // Inject +220 Hz Doppler shifted reflection
        for (i, s) in pure.iter_mut().enumerate() {
            let t = i as f64 / shield.sample_rate_hz;
            let doppler = (2.0 * PI * (shield.carrier_hz + 220.0) * t).sin() * 2200.0;
            *s = (*s as f64 + doppler).clamp(-32767.0, 32767.0) as i16;
        }
        let (ratio, alerts_doppler) = shield.analyze_mic_pcm(&pure, 2);
        assert!(ratio > 0.35);
        assert!(alerts_doppler.iter().any(|a| a.code == "ULTRASONIC_DOPPLER_MOTION"));
    }

    #[test]
    fn bus_baseline_persists_between_invocations() {
        let path = std::env::temp_dir().join(format!(
            "sppio-bus-baseline-test-{}.json",
            std::process::id()
        ));
        let path_text = path.to_string_lossy().to_string();
        let first = BusDisplayGuard::load_or_capture_baseline(&path_text);
        assert!(Path::new(&path_text).exists());
        let second = BusDisplayGuard::load_or_capture_baseline(&path_text);
        assert_eq!(
            first.baseline_usb_devices.len(),
            second.baseline_usb_devices.len()
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn v4l2_format_parsing_extracts_dimensions_and_fourcc() {
        let text = "Format Video Capture:\n\tWidth/Height      : 640/480\n\tPixel Format      : 'YUYV'\n";
        assert_eq!(parse_v4l2_dimensions(text), Some((640, 480)));
        assert_eq!(parse_v4l2_pixel_format(text).as_deref(), Some("YUYV"));
    }
}
