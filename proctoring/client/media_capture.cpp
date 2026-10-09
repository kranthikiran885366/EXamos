#include "../include/proctor.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <cerrno>
#include <sys/mman.h>
#include <sys/select.h>

namespace examos {
namespace proctoring {

MediaCapture::MediaCapture()
    : m_video_fd(-1), m_initialized(false), m_mmap_start(MAP_FAILED),
      m_mmap_length(0), m_width(0), m_height(0) {}

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

    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) ||
        !(cap.capabilities & V4L2_CAP_STREAMING)) {
        close_devices();
        return false;
    }

    struct v4l2_format fmt{};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 640;
    fmt.fmt.pix.height = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field = V4L2_FIELD_ANY;
    if (ioctl(m_video_fd, VIDIOC_S_FMT, &fmt) < 0 ||
        fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV) {
        close_devices();
        return false;
    }
    m_width = fmt.fmt.pix.width;
    m_height = fmt.fmt.pix.height;

    struct v4l2_requestbuffers req{};
    req.count = 1;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (ioctl(m_video_fd, VIDIOC_REQBUFS, &req) < 0 || req.count < 1) {
        close_devices();
        return false;
    }

    struct v4l2_buffer buf{};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = 0;
    if (ioctl(m_video_fd, VIDIOC_QUERYBUF, &buf) < 0) {
        close_devices();
        return false;
    }
    m_mmap_length = buf.length;
    m_mmap_start = mmap(nullptr, buf.length, PROT_READ | PROT_WRITE,
                        MAP_SHARED, m_video_fd, buf.m.offset);
    if (m_mmap_start == MAP_FAILED) {
        close_devices();
        return false;
    }
    if (ioctl(m_video_fd, VIDIOC_QBUF, &buf) < 0) {
        close_devices();
        return false;
    }
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(m_video_fd, VIDIOC_STREAMON, &type) < 0) {
        close_devices();
        return false;
    }
    m_rgb_frame.resize(static_cast<size_t>(m_width) * m_height * 3);

    m_initialized = true;
    return true;
}

bool MediaCapture::capture_frame(FrameStats &stats) {
    if (!m_initialized || m_video_fd < 0) {
        return false;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(m_video_fd, &fds);
    struct timeval timeout{2, 0};
    int ready;
    do { ready = select(m_video_fd + 1, &fds, nullptr, nullptr, &timeout); }
    while (ready < 0 && errno == EINTR);
    if (ready <= 0) return false;

    struct v4l2_buffer buf{};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    if (ioctl(m_video_fd, VIDIOC_DQBUF, &buf) < 0) return false;

    const auto *src = static_cast<const uint8_t *>(m_mmap_start);
    uint64_t luminance = 0;
    size_t pixels = static_cast<size_t>(m_width) * m_height;
    for (size_t p = 0, s = 0; p + 1 < pixels && s + 3 < buf.bytesused; p += 2, s += 4) {
        int y0 = src[s], u = src[s + 1] - 128, y1 = src[s + 2], v = src[s + 3] - 128;
        const int ys[2] = {y0, y1};
        for (int j = 0; j < 2; ++j) {
            int c = ys[j] - 16;
            int r = (298 * c + 409 * v + 128) >> 8;
            int g = (298 * c - 100 * u - 208 * v + 128) >> 8;
            int b = (298 * c + 516 * u + 128) >> 8;
            size_t d = (p + static_cast<size_t>(j)) * 3;
            m_rgb_frame[d] = static_cast<uint8_t>(std::max(0, std::min(255, r)));
            m_rgb_frame[d + 1] = static_cast<uint8_t>(std::max(0, std::min(255, g)));
            m_rgb_frame[d + 2] = static_cast<uint8_t>(std::max(0, std::min(255, b)));
            luminance += static_cast<uint64_t>(ys[j]);
        }
    }
    stats.width = m_width;
    stats.height = m_height;
    stats.mean_luminance = pixels ? static_cast<float>(luminance) / pixels : 0.0f;
    stats.detected_faces = 0;
    stats.gaze_angle_x = 0.0f;
    stats.gaze_angle_y = 0.0f;
    bool queued = ioctl(m_video_fd, VIDIOC_QBUF, &buf) == 0;
    return queued;
}

const uint8_t *MediaCapture::frame_data() const { return m_rgb_frame.data(); }
size_t MediaCapture::frame_size() const { return m_rgb_frame.size(); }
uint32_t MediaCapture::frame_stride() const { return m_width * 3; }
uint32_t MediaCapture::frame_channels() const { return 3; }

/* P4-SCOPE: ALSA/PipeWire audio capture and energy computation. */
bool MediaCapture::capture_audio(AudioStats &stats) {
    (void)stats;
    return false;
}

void MediaCapture::close_devices() {
    if (m_video_fd >= 0) {
        enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (m_initialized) ioctl(m_video_fd, VIDIOC_STREAMOFF, &type);
        if (m_mmap_start != MAP_FAILED) {
            munmap(m_mmap_start, m_mmap_length);
            m_mmap_start = MAP_FAILED;
            m_mmap_length = 0;
        }
        close(m_video_fd);
        m_video_fd = -1;
    }
    m_initialized = false;
    m_rgb_frame.clear();
}

} // namespace proctoring
} // namespace examos
