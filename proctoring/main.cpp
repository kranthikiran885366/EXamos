#include "include/proctor.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <csignal>
#include <iomanip>

static volatile std::sig_atomic_t g_proctor_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_proctor_running = 0;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    std::signal(SIGTERM, sig_handler);
    std::signal(SIGINT, sig_handler);

    std::cout << "[ExamOS-Proctor] Proctoring measurements are unavailable until real capture and analysis are implemented." << std::endl;

    examos::proctoring::MediaCapture capture;
    if (!capture.initialize("/dev/video0")) {
        std::cerr << "[ExamOS-Proctor] Camera unavailable; refusing to synthesize candidate-presence data." << std::endl;
        return 1;
    }

    examos::proctoring::FrameStats frame{};
    if (!capture.capture_frame(frame)) {
        std::cerr << "[ExamOS-Proctor] Real frame capture and face analysis are not implemented." << std::endl;
        return 1;
    }

    capture.close_devices();
    return 1;
}
