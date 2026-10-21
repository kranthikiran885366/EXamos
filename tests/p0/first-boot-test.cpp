#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <regex>
#include <string>
#include <thread>
#include <vector>

namespace {

bool send_text(int socket, const std::string& text) {
    std::size_t offset = 0;
    while (offset < text.size()) {
        const auto sent = send(socket, text.data() + offset, text.size() - offset, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

bool wait_for_text(int socket, FILE* log, std::string& transcript,
                   const std::string& marker, int timeout_seconds) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(timeout_seconds);
    std::vector<char> buffer(4096);
    while (std::chrono::steady_clock::now() < deadline) {
        if (transcript.find(marker) != std::string::npos) {
            return true;
        }
        struct pollfd descriptor { socket, POLLIN, 0 };
        const int ready = poll(&descriptor, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (ready == 0) {
            continue;
        }
        const auto received = recv(socket, buffer.data(), buffer.size(), 0);
        if (received <= 0) {
            return false;
        }
        if (fwrite(buffer.data(), 1, static_cast<std::size_t>(received), log) !=
            static_cast<std::size_t>(received)) {
            return false;
        }
        transcript.append(buffer.data(), static_cast<std::size_t>(received));
        if (transcript.size() > 2 * 1024 * 1024) {
            transcript.erase(0, transcript.size() - 1024 * 1024);
        }
    }
    return transcript.find(marker) != std::string::npos;
}

std::string make_test_username() {
    unsigned char random[12] {};
    std::size_t filled = 0;
    while (filled < sizeof(random)) {
        const auto count = getrandom(random + filled, sizeof(random) - filled, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {};
        }
        filled += static_cast<std::size_t>(count);
    }

    std::string username;
    username.reserve(sizeof(random));
    for (const auto value : random) {
        username.push_back(static_cast<char>('a' + (value % 26)));
    }
    return username;
}

std::string make_test_password() {
    constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string password = "ExamOS-P0-";
    unsigned char random[16] {};
    std::size_t filled = 0;
    while (filled < sizeof(random)) {
        const auto count = getrandom(random + filled, sizeof(random) - filled, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {};
        }
        filled += static_cast<std::size_t>(count);
    }
    for (const auto value : random) {
        password.push_back(alphabet[value % (sizeof(alphabet) - 1)]);
    }
    password.push_back('!');
    return password;
}

bool redact_password(const char* path, const std::string& password) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    std::string contents((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
    std::size_t offset = 0;
    while ((offset = contents.find(password, offset)) != std::string::npos) {
        contents.replace(offset, password.size(), "[REDACTED]");
        offset += sizeof("[REDACTED]") - 1;
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    return output.good();
}

bool wait_for_login_result(int socket, FILE* log, std::string& transcript) {
    const std::regex result_line(
        R"((^|\n)EXAMOS_P0_LOGIN_OK=([1-9][0-9]*)\|([^|\r\n]*)\|([^\r\n]*))");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
    std::vector<char> buffer(4096);
    std::smatch match;
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::regex_search(transcript, match, result_line)) {
            const std::string uid = match[2].str();
            const std::string groups = match[3].str();
            const std::regex sudo_group(R"((^|\s)sudo(\s|$))");
            const bool non_root_uid =
                uid.size() > 4 || (uid.size() == 4 && uid >= "1000");
            return non_root_uid &&
                   std::regex_search(groups, sudo_group) &&
                   match[4].str() == "0:0:755";
        }
        struct pollfd descriptor { socket, POLLIN, 0 };
        const int ready = poll(&descriptor, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (ready == 0) {
            continue;
        }
        const auto received = recv(socket, buffer.data(), buffer.size(), 0);
        if (received <= 0 ||
            fwrite(buffer.data(), 1, static_cast<std::size_t>(received), log) !=
                static_cast<std::size_t>(received)) {
            return false;
        }
        transcript.append(buffer.data(), static_cast<std::size_t>(received));
        if (transcript.size() > 2 * 1024 * 1024) {
            transcript.erase(0, transcript.size() - 1024 * 1024);
        }
    }
    return false;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::strcmp(argv[1], "--allocate-port") == 0) {
        const int port_socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (port_socket < 0) {
            std::perror("cannot create ephemeral-port socket");
            return 1;
        }
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (bind(port_socket, reinterpret_cast<sockaddr*>(&address),
                 sizeof(address)) != 0) {
            std::perror("cannot reserve ephemeral serial port");
            close(port_socket);
            return 1;
        }
        socklen_t address_size = sizeof(address);
        if (getsockname(port_socket, reinterpret_cast<sockaddr*>(&address),
                        &address_size) != 0) {
            std::perror("cannot inspect ephemeral serial port");
            close(port_socket);
            return 1;
        }
        std::cout << ntohs(address.sin_port) << '\n';
        close(port_socket);
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--make-username") == 0) {
        const auto username = make_test_username();
        if (username.empty()) {
            std::cerr << "cannot generate a one-time test username\n";
            return 1;
        }
        std::cout << username << '\n';
        return 0;
    }
    const bool resume = argc == 5 && std::strcmp(argv[1], "--resume") == 0;
    if ((!resume && argc != 3) || (resume && argc != 5)) {
        std::cerr << "usage: first-boot-test PORT LOG | --resume PORT USERNAME LOG | "
                     "--allocate-port | --make-username\n";
        return 2;
    }
    const char* port_argument = resume ? argv[2] : argv[1];
    const char* log_path = resume ? argv[4] : argv[2];
    char* end = nullptr;
    const long port = std::strtol(port_argument, &end, 10);
    if (end == port_argument || *end != '\0' || port < 1 || port > 65535) {
        std::cerr << "invalid serial test arguments\n";
        return 2;
    }

    const std::string username = resume ? argv[3] : make_test_username();
    const std::regex valid_username(R"([a-z_][a-z0-9_-]{0,31})");
    if (!std::regex_match(username, valid_username) || username == "root") {
        std::cerr << "invalid test username\n";
        return 2;
    }
    const std::string password = make_test_password();
    if (username.empty() || password.empty()) {
        std::cerr << "cannot generate one-time test credentials\n";
        return 1;
    }
    FILE* log = std::fopen(log_path, "wb");
    if (log == nullptr) {
        std::perror("cannot open serial evidence log");
        return 1;
    }
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int socket_fd = -1;
    bool connected = false;
    const auto connect_deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < connect_deadline) {
        socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (socket_fd < 0) {
            std::perror("cannot create serial socket");
            std::fclose(log);
            return 1;
        }
        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&address),
                    sizeof(address)) == 0) {
            connected = true;
            break;
        }
        const int connect_error = errno;
        close(socket_fd);
        socket_fd = -1;
        if (connect_error != ECONNREFUSED && connect_error != EINTR) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!connected) {
        std::cerr << "cannot connect to QEMU serial TCP console\n";
        close(socket_fd);
        std::fclose(log);
        return 1;
    }

    std::string transcript;
    bool success = true;
    if (resume) {
        success = wait_for_text(socket_fd, log, transcript,
                                "Account " + username +
                                    " is missing; repairing interrupted first-boot setup.", 180) &&
                  wait_for_text(socket_fd, log, transcript,
                                "Resuming account setup for " + username +
                                    " after an interrupted first boot.", 30);
    } else {
        success = wait_for_text(socket_fd, log, transcript,
                                "New username (45-second timeout):", 150) &&
                  send_text(socket_fd, username + "\n");
    }
    success = success &&
        wait_for_text(socket_fd, log, transcript, "New password:", 30) &&
        send_text(socket_fd, password + "\n") &&
        wait_for_text(socket_fd, log, transcript, "Retype new password:", 30) &&
        send_text(socket_fd, password + "\n") &&
        wait_for_text(socket_fd, log, transcript,
                      "Development account " + username + " is ready.", 45) &&
        wait_for_text(socket_fd, log, transcript, " login:", 30) &&
        send_text(socket_fd, username + "\n") &&
        wait_for_text(socket_fd, log, transcript, "Password:", 30) &&
        send_text(socket_fd, password + "\n");
    if (success) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        success = send_text(socket_fd,
                            "printf '\\nEXAMOS_P0_LOGIN_OK=%s|%s|%s\\n' "
                            "\"$(id -u)\" \"$(id -nG)\" "
                            "\"$(stat -c '%u:%g:%a' /usr/local/sbin/"
                            "examos-dev-console-setup)\"\n") &&
                  wait_for_login_result(socket_fd, log, transcript);
    }

    std::fflush(log);
    close(socket_fd);
    std::fclose(log);
    if (!redact_password(log_path, password)) {
        std::remove(log_path);
        std::cerr << "cannot safely redact the temporary test password from the log\n";
        return 1;
    }
    if (!success) {
        std::cerr << "serial account creation or authenticated login failed; "
                     "inspect the first-boot log\n";
        return 1;
    }
    std::cout << "First-boot account created and authenticated login verified.\n";
    return 0;
}
