#ifndef EXAMOS_RISK_ENGINE_H
#define EXAMOS_RISK_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int attestation_failed;
    int external_display_active;
    int usb_storage_connected;
    int face_absent_count;
    int multiple_faces_count;
    int gaze_deviation_count;
    int rf_anomaly_detected;
} violation_indicators_t;

typedef struct {
    float composite_risk_score; // 0.0 (Safe) to 1.0 (Critical Threat)
    const char *risk_level;     // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    int should_terminate_exam;
} risk_assessment_t;

void risk_engine_evaluate(const violation_indicators_t *indicators, risk_assessment_t *assessment);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_RISK_ENGINE_H
