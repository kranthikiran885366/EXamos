#ifndef EXAMOS_PROCTOR_H
#define EXAMOS_PROCTOR_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

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
    const uint8_t *frame_data() const;
    size_t frame_size() const;
    uint32_t frame_stride() const;
    uint32_t frame_channels() const;
    bool capture_audio(AudioStats &stats);
    void close_devices();

private:
    int m_video_fd;
    bool m_initialized;
    void *m_mmap_start;
    size_t m_mmap_length;
    std::vector<uint8_t> m_rgb_frame;
    uint32_t m_width;
    uint32_t m_height;
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
