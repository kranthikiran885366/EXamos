#ifndef EXAMOS_PROCTOR_H
#define EXAMOS_PROCTOR_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace examos {
namespace proctoring {

/*
 * Frame geometry only. Detection results (faces, gaze, objects) come from the
 * vision engine, which either reports what a verified model matched or reports
 * the analysis as unavailable. No proctoring signal is derived from a
 * brightness heuristic or from an unpopulated struct field.
 */
struct FrameStats {
    uint32_t width;
    uint32_t height;
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
    void close_devices();

private:
    int m_video_fd;
    bool m_initialized;
    void *m_mmap_start;
    size_t m_mmap_length;
    std::vector<uint8_t> m_rgb_frame;
    uint32_t m_width;
    uint32_t m_height;
    /* Regular-file capture is used by the evaluation harness.  The pointer is
       an OpenCV VideoCapture kept opaque here so the public header does not
       pull OpenCV into every translation unit that uses MediaCapture. */
    void *m_file_capture;
    bool m_file_mode;
};

} // namespace proctoring
} // namespace examos

#endif // EXAMOS_PROCTOR_H
