#![forbid(unsafe_code)]
//! Offline On-Device Behavioral AI Engine
//!
//! Runs completely offline inside the privileged Rust security boundary:
//! 1. BadUSB / HID Keystroke-Injection Classifier: extracts inter-keystroke interval (IKI),
//!    hold duration variance, sub-10ms burst ratio, timing entropy and USB HID identity to
//!    detect programmable HID injectors (e.g., Rubber Ducky, Bash Bunny, O.MG cables).
//! 2. Wayland Screen-Overlay & Compositor Tamper Classifier: evaluates unauthorized surface
//!    layer-shell injections, focus-steal bursts, and frame-capture timing anomalies.
//!
//! The scoring models are small, interpretable logistic scorers with documented
//! feature weights; they are not advertised as trained neural networks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeSample {
    pub timestamp_us: u64,
    pub hold_duration_us: u64,
    pub keycode: u16,
    pub hid_vendor_id: u16,
    pub hid_product_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatVerdict {
    Benign,
    Suspicious,
    CriticalAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAssessment {
    pub verdict: ThreatVerdict,
    pub probability: f64,
    pub detector: &'static str,
    pub features: Vec<(&'static str, f64)>,
    pub reason: String,
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// Evaluates a sliding window of HID keystroke events for BadUSB / automated injection.
pub fn assess_keystroke_window(samples: &[KeystrokeSample]) -> BehavioralAssessment {
    if samples.len() < 8 {
        return BehavioralAssessment {
            verdict: ThreatVerdict::Benign,
            probability: 0.0,
            detector: "badusb_hid_heuristic",
            features: vec![("sample_count", samples.len() as f64)],
            reason: "Insufficient keystroke window for inference".to_string(),
        };
    }

    let mut ikis = Vec::with_capacity(samples.len() - 1);
    let mut sub_10ms_count = 0usize;
    let mut sub_3ms_count = 0usize;
    let mut uniform_hold_count = 0usize;

    for w in samples.windows(2) {
        let delta_us = w[1].timestamp_us.saturating_sub(w[0].timestamp_us);
        ikis.push(delta_us as f64);
        if delta_us < 10_000 {
            sub_10ms_count += 1;
        }
        if delta_us < 3_000 {
            sub_3ms_count += 1;
        }
        if w[1].hold_duration_us.abs_diff(w[0].hold_duration_us) < 250 {
            uniform_hold_count += 1;
        }
    }

    let n = ikis.len() as f64;
    let mean_iki_ms = (ikis.iter().sum::<f64>() / n) / 1000.0;
    let variance = ikis
        .iter()
        .map(|&x| {
            let diff = (x / 1000.0) - mean_iki_ms;
            diff * diff
        })
        .sum::<f64>()
        / n;
    let std_iki_ms = variance.sqrt();
    let burst_ratio = sub_10ms_count as f64 / n;
    let robotic_ratio = sub_3ms_count as f64 / n;
    let hold_uniformity = uniform_hold_count as f64 / n;

    // The HID identity is part of the feature vector: programmable boards and
    // devices that report no vendor/product identity are weighted upward. A
    // homogeneous unknown identity across the whole window is a stronger
    // signal than a single odd event, because a real keyboard does not change
    // its USB identity mid-session.
    let first_vendor = samples[0].hid_vendor_id;
    let first_product = samples[0].hid_product_id;
    let homogeneous_identity = samples
        .iter()
        .all(|s| s.hid_vendor_id == first_vendor && s.hid_product_id == first_product);
    let programmable_hid_identity = matches!(first_vendor, 0x16c0 | 0x1d50 | 0x1209 | 0x2341);
    let hid_identity_risk = if first_vendor == 0 && first_product == 0 {
        1.0
    } else if homogeneous_identity && programmable_hid_identity {
        1.0
    } else {
        0.0
    };

    // Calibrated logistic scorer over timing features (not a trained neural
    // network). Human typing: mean IKI ~80-250ms, std >25ms, burst_ratio ~0,
    // hold_uniformity <0.25. BadUSB injection: mean IKI <15ms, std <5ms,
    // burst_ratio >0.6, hold_uniformity >0.6.
    let z = -3.2
        + 4.8 * burst_ratio
        + 5.5 * robotic_ratio
        + 2.4 * hold_uniformity
        + 1.8 * hid_identity_risk
        + if mean_iki_ms < 20.0 { 2.2 } else { -0.8 }
        + if std_iki_ms < 4.0 { 2.0 } else { -0.6 };

    let prob = sigmoid(z);
    let verdict = if prob >= 0.85 {
        ThreatVerdict::CriticalAttack
    } else if prob >= 0.55 {
        ThreatVerdict::Suspicious
    } else {
        ThreatVerdict::Benign
    };

    let reason = match verdict {
        ThreatVerdict::CriticalAttack => format!(
            "Automated HID keystroke injection detected (mean_iki={mean_iki_ms:.2}ms, std={std_iki_ms:.2}ms, burst_ratio={burst_ratio:.2})"
        ),
        ThreatVerdict::Suspicious => format!(
            "Anomalous keystroke cadence (mean_iki={mean_iki_ms:.2}ms, burst_ratio={burst_ratio:.2})"
        ),
        ThreatVerdict::Benign => "Human typing cadence within normal distribution".to_string(),
    };

    BehavioralAssessment {
        verdict,
        probability: prob,
        detector: "badusb_hid_heuristic",
        features: vec![
            ("mean_iki_ms", mean_iki_ms),
            ("std_iki_ms", std_iki_ms),
            ("sub_10ms_burst_ratio", burst_ratio),
            ("sub_3ms_robotic_ratio", robotic_ratio),
            ("hold_uniformity", hold_uniformity),
            ("hid_identity_risk", hid_identity_risk),
        ],
        reason,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaylandSurfaceTelemetry {
    pub total_surfaces: u32,
    pub unauthorized_layer_shells: u32,
    pub focus_steals_per_min: u32,
    pub screencopy_requests: u32,
    pub compositor_frame_jitter_ms: f64,
}

/// Evaluates Wayland / Cage compositor telemetry for screen-overlay or capture attacks.
pub fn assess_overlay_telemetry(t: &WaylandSurfaceTelemetry) -> BehavioralAssessment {
    let extra_surfaces = t.total_surfaces.saturating_sub(1) as f64;
    let z = -4.0
        + 6.0 * (t.unauthorized_layer_shells as f64).min(2.0)
        + 4.5 * (t.screencopy_requests as f64).min(2.0)
        + 1.8 * extra_surfaces.min(3.0)
        + 0.4 * (t.focus_steals_per_min as f64).min(10.0)
        + if t.compositor_frame_jitter_ms > 25.0 { 1.1 } else { 0.0 };

    let prob = sigmoid(z);
    let verdict = if prob >= 0.85 {
        ThreatVerdict::CriticalAttack
    } else if prob >= 0.55 {
        ThreatVerdict::Suspicious
    } else {
        ThreatVerdict::Benign
    };

    BehavioralAssessment {
        verdict: verdict.clone(),
        probability: prob,
        detector: "wayland_overlay_heuristic",
        features: vec![
            ("total_surfaces", t.total_surfaces as f64),
            ("unauthorized_layer_shells", t.unauthorized_layer_shells as f64),
            ("focus_steals_per_min", t.focus_steals_per_min as f64),
            ("screencopy_requests", t.screencopy_requests as f64),
            ("frame_jitter_ms", t.compositor_frame_jitter_ms),
        ],
        reason: if verdict == ThreatVerdict::Benign {
            "Single Cage kiosk Wayland surface verified; no overlay or screencopy activity".to_string()
        } else {
            format!(
                "Wayland overlay/capture anomaly (layer_shells={}, screencopy={}, surfaces={})",
                t.unauthorized_layer_shells, t.screencopy_requests, t.total_surfaces
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_badusb_keystroke_injection() {
        let mut badusb = Vec::new();
        for i in 0..24 {
            badusb.push(KeystrokeSample {
                timestamp_us: i * 1_800, // 1.8ms uniform robotic cadence
                hold_duration_us: 1_000,
                keycode: 30 + (i as u16 % 10),
                hid_vendor_id: 0x16c0,
                hid_product_id: 0x0486,
            });
        }
        let res = assess_keystroke_window(&badusb);
        assert_eq!(res.verdict, ThreatVerdict::CriticalAttack);
        assert!(res.probability >= 0.85);
    }

    #[test]
    fn allows_human_typing_cadence() {
        let deltas_ms = [120u64, 185, 95, 210, 145, 310, 112, 168, 194, 133, 240, 155];
        let holds_ms = [65u64, 82, 54, 91, 70, 60, 88, 73, 59, 85, 67, 79];
        let mut t = 1_000_000u64;
        let samples: Vec<_> = deltas_ms
            .iter()
            .zip(holds_ms.iter())
            .enumerate()
            .map(|(i, (d, h))| {
                t += d * 1000;
                KeystrokeSample {
                    timestamp_us: t,
                    hold_duration_us: h * 1000,
                    keycode: 20 + i as u16,
                    hid_vendor_id: 0x046d,
                    hid_product_id: 0xc31c,
                }
            })
            .collect();
        let res = assess_keystroke_window(&samples);
        assert_eq!(res.verdict, ThreatVerdict::Benign);
        assert!(res.probability < 0.55);
    }

    #[test]
    fn detects_wayland_overlay_and_screencopy_attack() {
        let attack = WaylandSurfaceTelemetry {
            total_surfaces: 2,
            unauthorized_layer_shells: 1,
            focus_steals_per_min: 3,
            screencopy_requests: 1,
            compositor_frame_jitter_ms: 31.4,
        };
        let res = assess_overlay_telemetry(&attack);
        assert_eq!(res.verdict, ThreatVerdict::CriticalAttack);
    }

    #[test]
    fn labeled_dataset_meets_false_positive_and_recall_targets() {
        let mut fp = 0usize;
        let mut tn = 0usize;
        for seed in 0..20usize {
            let mut human = Vec::new();
            let mut ts = 1_000_000u64;
            for i in 0..20usize {
                ts += 95_000 + ((i * 17 + seed * 31) % 90) as u64 * 1_000;
                human.push(KeystrokeSample {
                    timestamp_us: ts,
                    hold_duration_us: 65_000 + ((i * 23 + seed * 11) % 35) as u64 * 1_000,
                    keycode: (30 + (i % 26)) as u16,
                    hid_vendor_id: 0x046d,
                    hid_product_id: 0xc31c,
                });
            }
            if assess_keystroke_window(&human).verdict == ThreatVerdict::CriticalAttack {
                fp += 1;
            } else {
                tn += 1;
            }
        }
        let fpr = fp as f64 / (fp + tn) as f64;
        assert!(fpr <= 0.01, "False-positive rate {fpr:.3} exceeded 1%");

        let mut tp = 0usize;
        for i_set in 0..20usize {
            let mut badusb = Vec::new();
            let mut ts = 1_000_000u64;
            for i in 0..20usize {
                ts += 1_500 + (i_set % 3) as u64 * 500;
                badusb.push(KeystrokeSample {
                    timestamp_us: ts,
                    hold_duration_us: 2_000,
                    keycode: (30 + (i % 26)) as u16,
                    hid_vendor_id: 0x16c0,
                    hid_product_id: 0x27db,
                });
            }
            if assess_keystroke_window(&badusb).verdict == ThreatVerdict::CriticalAttack {
                tp += 1;
            }
        }
        let recall = tp as f64 / 20.0;
        assert!(recall >= 0.95, "Recall {recall:.3} below 95%");
    }
}
