#include "../include/proctor.h"
#include <ctime>
#include <cmath>

namespace examos {
namespace proctoring {

AnomalyDetector::AnomalyDetector() : m_absent_frame_count(0), m_audio_violation_count(0) {}

std::vector<AnomalyEvent> AnomalyDetector::evaluate(const FrameStats &frame, const AudioStats &audio) {
    std::vector<AnomalyEvent> events;
    long now = static_cast<long>(std::time(nullptr));

    // 1. Face Presence Verification
    if (frame.detected_faces == 0) {
        m_absent_frame_count++;
        if (m_absent_frame_count > 5) { // 5 consecutive frames absent
            events.push_back({
                now,
                AnomalyType::FACE_ABSENT,
                0.95f,
                "Candidate face not detected in webcam field of view"
            });
        }
    } else {
        m_absent_frame_count = 0;
    }

    // 2. Multiple Face Detection
    if (frame.detected_faces > 1) {
        events.push_back({
            now,
            AnomalyType::MULTIPLE_FACES,
            0.98f,
            "Multiple faces detected in examination room"
        });
    }

    // 3. Gaze Deviation (Look-away) Analysis
    if (std::abs(frame.gaze_angle_x) > 35.0f || std::abs(frame.gaze_angle_y) > 30.0f) {
        events.push_back({
            now,
            AnomalyType::GAZE_DEVIATION,
            0.85f,
            "Suspicious head/gaze orientation deviation from primary screen"
        });
    }

    // 4. Acoustic Voice & Noise Level Detection
    if (audio.voice_activity || audio.peak_energy_db > -20.0f) {
        m_audio_violation_count++;
        if (m_audio_violation_count > 3) {
            events.push_back({
                now,
                AnomalyType::AUDIO_VOICE_DETECTED,
                0.90f,
                "Acoustic threshold exceeded: human voice or speech detected"
            });
        }
    } else {
        m_audio_violation_count = 0;
    }

    return events;
}

} // namespace proctoring
} // namespace examos
