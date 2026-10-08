#include "../include/proctor.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>
#include <cstring>
#include <cmath>

namespace examos {
namespace proctoring {

MediaCapture::MediaCapture() : m_video_fd(-1), m_initialized(false) {}

MediaCapture::~MediaCapture() {
    close_devices();
}

bool MediaCapture::initialize(const std::string &video_dev) {
    m_video_fd = open(video_dev.c_str(), O_RDWR | O_NONBLOCK, 0);
    if (m_video_fd < 0) {
        // Fallback: Video device may not be present in virtual environment or non-camera setup
        m_initialized = false;
        return false;
    }

    struct v4l2_capability cap;
    if (ioctl(m_video_fd, VIDIOC_QUERYCAP, &cap) < 0) {
        close(m_video_fd);
        m_video_fd = -1;
        m_initialized = false;
        return false;
    }

    m_initialized = true;
    return true;
}

/* P4-SCOPE: Full V4L2 mmap buffer ring, frame dequeue, and face detection pipeline. */
bool MediaCapture::capture_frame(FrameStats &stats) {
    if (!m_initialized || m_video_fd < 0) {
        return false;
    }

    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(m_video_fd, VIDIOC_G_FMT, &fmt) < 0) return false;

    (void)stats;
    return false;
}

/* P4-SCOPE: ALSA/PipeWire audio capture and energy computation. */
bool MediaCapture::capture_audio(AudioStats &stats) {
    (void)stats;
    return false;
}

void MediaCapture::close_devices() {
    if (m_video_fd >= 0) {
        close(m_video_fd);
        m_video_fd = -1;
    }
    m_initialized = false;
}

} // namespace proctoring
} // namespace examos
