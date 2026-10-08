#ifndef EXAMOS_PROCTOR_H
#define EXAMOS_PROCTOR_H

#include <string>
#include <vector>
#include <cstdint>

namespace examos {
namespace proctoring {

enum class AnomalyType {
    NONE = 0,
    FACE_ABSENT,
    MULTIPLE_FACES,
    GAZE_DEVIATION,
    AUDIO_VOICE_DETECTED,
    SCREEN_COVERED
};

struct AnomalyEvent {
    long timestamp;
    AnomalyType type;
    float confidence;
    std::string description;
};

struct FrameStats {
    uint32_t width;
    uint32_t height;
    float mean_luminance;
    int detected_faces;
    float gaze_angle_x;
    float gaze_angle_y;
};

struct AudioStats {
    float peak_energy_db;
    bool voice_activity;
};

class MediaCapture {
public:
    MediaCapture();
    ~MediaCapture();
    bool initialize(const std::string &video_dev = "/dev/video0");
    bool capture_frame(FrameStats &stats);
    bool capture_audio(AudioStats &stats);
    void close_devices();

private:
    int m_video_fd;
    bool m_initialized;
};

class AnomalyDetector {
public:
    AnomalyDetector();
    std::vector<AnomalyEvent> evaluate(const FrameStats &frame, const AudioStats &audio);

private:
    int m_absent_frame_count;
    int m_audio_violation_count;
};

} // namespace proctoring
} // namespace examos

#endif // EXAMOS_PROCTOR_H
