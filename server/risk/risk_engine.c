#include "../include/risk_engine.h"

void risk_engine_evaluate(const violation_indicators_t *indicators, risk_assessment_t *assessment) {
    if (!indicators || !assessment) return;

    float score = 0.0f;

    // Critical Invariant: TPM / Kernel Attestation Failure (Weight: 0.60)
    if (indicators->attestation_failed) {
        score += 0.60f;
    }

    // Hardware Lockdown: Unauthorized USB Mass Storage (Weight: 0.35)
    if (indicators->usb_storage_connected) {
        score += 0.35f;
    }

    // Hardware Lockdown: Multi-monitor / Secondary Screen (Weight: 0.30)
    if (indicators->external_display_active) {
        score += 0.30f;
    }

    // Proctoring: Multiple Faces Detected (Weight: 0.40)
    if (indicators->multiple_faces_count > 0) {
        score += 0.40f;
    }

    // Proctoring: Candidate Absent (Weight: 0.25)
    if (indicators->face_absent_count > 3) {
        score += 0.25f;
    }

    // Proctoring: Repeated Gaze Deviations (Weight: 0.15)
    if (indicators->gaze_deviation_count > 5) {
        score += 0.15f;
    }

    // Environment: Unexpected RF/BLE devices (Weight: 0.10)
    if (indicators->rf_anomaly_detected) {
        score += 0.10f;
    }

    if (score > 1.0f) score = 1.0f;

    assessment->composite_risk_score = score;

    if (score >= 0.75f) {
        assessment->risk_level = "CRITICAL";
        assessment->should_terminate_exam = 1;
    } else if (score >= 0.50f) {
        assessment->risk_level = "HIGH";
        assessment->should_terminate_exam = 0;
    } else if (score >= 0.25f) {
        assessment->risk_level = "MEDIUM";
        assessment->should_terminate_exam = 0;
    } else {
        assessment->risk_level = "LOW";
        assessment->should_terminate_exam = 0;
    }
}
