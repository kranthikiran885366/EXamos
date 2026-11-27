#include "../include/proctor.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/videodev2.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <cerrno>
#include <sys/mman.h>
#include <sys/select.h>
#include <opencv2/videoio.hpp>
#include <opencv2/imgproc.hpp>

namespace examos {
namespace proctoring {

MediaCapture::MediaCapture()
    : m_video_fd(-1), m_initialized(false), m_mmap_start(MAP_FAILED),
      m_mmap_length(0), m_width(0), m_height(0),
      m_file_capture(nullptr), m_file_mode(false) {}

MediaCapture::~MediaCapture() {
    close_devices();
}

bool MediaCapture::initialize(const std::string &video_dev) {
    /* A regular file (used by the labelled-clip evaluation harness) is read
       through OpenCV's VideoCapture.  Character devices continue down the
       V4L2 path below. */
    struct stat path_stat {};
    if (stat(video_dev.c_str(), &path_stat) == 0 && S_ISREG(path_stat.st_mode)) {
        auto *capture = new cv::VideoCapture(video_dev);
        if (!capture->isOpened()) {
            delete capture;
            m_initialized = false;
            return false;
        }
        cv::Mat first;
        if (!capture->read(first) || first.empty()) {
            capture->release();
            delete capture;
            m_initialized = false;
            return false;
        }
        m_width = static_cast<uint32_t>(first.cols);
        m_height = static_cast<uint32_t>(first.rows);
        m_file_capture = capture;
        m_file_mode = true;
        m_rgb_frame.resize(static_cast<size_t>(m_width) * m_height * 3);
        /* VideoCapture returns BGR, which is the layout the vision engine
           expects.  Convert to 3-channel BGR if necessary and use copyTo
           for continuous-memory safety (isContinuous() may be false for
           sub-matrices or padded rows). */
        {
            cv::Mat bgr3;
            if (first.channels() == 4) {
                cv::cvtColor(first, bgr3, cv::COLOR_BGRA2BGR);
            } else if (first.channels() == 1) {
                cv::cvtColor(first, bgr3, cv::COLOR_GRAY2BGR);
            } else if (first.channels() == 3) {
                bgr3 = first;
            } else {
                capture->release();
                delete capture;
                m_initialized = false;
                return false;
            }
            if (!bgr3.isContinuous()) {
                bgr3 = bgr3.clone();
            }
            std::memcpy(m_rgb_frame.data(), bgr3.data, m_rgb_frame.size());
        }
        m_initialized = true;
        return true;
    }

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
    if (!m_initialized) {
        return false;
    }

    if (m_file_mode) {
        auto *capture = static_cast<cv::VideoCapture *>(m_file_capture);
        if (!capture) return false;
        cv::Mat frame;
        if (!capture->read(frame) || frame.empty()) {
            /* Loop the clip: a 3-second evaluation clip is sampled once per
               second, so reaching EOF before the harness stops the worker is
               expected rather than an error. */
            capture->set(cv::CAP_PROP_POS_FRAMES, 0);
            if (!capture->read(frame) || frame.empty()) return false;
        }
        m_width = static_cast<uint32_t>(frame.cols);
        m_height = static_cast<uint32_t>(frame.rows);
        const size_t needed = static_cast<size_t>(m_width) * m_height * 3;
        if (m_rgb_frame.size() != needed) m_rgb_frame.resize(needed);
        /* Ensure the frame is 3-channel BGR and contiguous before copying. */
        {
            cv::Mat bgr3;
            if (frame.channels() == 4) {
                cv::cvtColor(frame, bgr3, cv::COLOR_BGRA2BGR);
            } else if (frame.channels() == 1) {
                cv::cvtColor(frame, bgr3, cv::COLOR_GRAY2BGR);
            } else if (frame.channels() == 3) {
                bgr3 = frame;
            } else {
                return false;
            }
            if (!bgr3.isContinuous()) {
                bgr3 = bgr3.clone();
            }
            std::memcpy(m_rgb_frame.data(), bgr3.data, needed);
        }
        stats.width = m_width;
        stats.height = m_height;
        return true;
    }

    if (m_video_fd < 0) {
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
            /* Store BGR: OpenCV's video path and the vision engine both use
               BGR, so a YUYV frame must not be handed over as RGB. */
            m_rgb_frame[d] = static_cast<uint8_t>(std::max(0, std::min(255, b)));
            m_rgb_frame[d + 1] = static_cast<uint8_t>(std::max(0, std::min(255, g)));
            m_rgb_frame[d + 2] = static_cast<uint8_t>(std::max(0, std::min(255, r)));
            luminance += static_cast<uint64_t>(ys[j]);
        }
    }
    stats.width = m_width;
    stats.height = m_height;
    (void)luminance;
    (void)pixels;
    bool queued = ioctl(m_video_fd, VIDIOC_QBUF, &buf) == 0;
    return queued;
}

const uint8_t *MediaCapture::frame_data() const { return m_rgb_frame.data(); }
size_t MediaCapture::frame_size() const { return m_rgb_frame.size(); }
uint32_t MediaCapture::frame_stride() const { return m_width * 3; }
uint32_t MediaCapture::frame_channels() const { return 3; }

void MediaCapture::close_devices() {
    if (m_file_capture) {
        auto *capture = static_cast<cv::VideoCapture *>(m_file_capture);
        capture->release();
        delete capture;
        m_file_capture = nullptr;
    }
    m_file_mode = false;
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
