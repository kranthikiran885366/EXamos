#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <shadow.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr char kStateDirectory[] = "/var/lib/examos";
constexpr char kStateFile[] = "dev-console-user-created";
constexpr int kUsernameTimeoutSeconds = 45;

void report(const char* message) {
    dprintf(STDERR_FILENO, "ExamOS development account setup: %s\n", message);
}

bool safe_state_directory(int directory) {
    struct stat status {};
    if (fstat(directory, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != 0 || (status.st_mode & 0022) != 0) {
        report("setup state directory has unsafe ownership or permissions");
        return false;
    }
    return true;
}

bool valid_username(std::string_view username) {
    if (username.empty() || username.size() > 32 || username == "root") {
        return false;
    }
    const auto first = username.front();
    if (!((first >= 'a' && first <= 'z') || first == '_')) {
        return false;
    }
    for (const char character : username) {
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              character == '_' || character == '-')) {
            return false;
        }
    }
    return true;
}

bool valid_console_path(std::string_view path) {
    constexpr std::string_view prefix = "/dev/tty";
    if (path.size() <= prefix.size() || path.substr(0, prefix.size()) != prefix) {
        return false;
    }
    for (const char character : path.substr(prefix.size())) {
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              character == '.' || character == '_' || character == '-')) {
            return false;
        }
    }
    struct stat status {};
    return stat(std::string(path).c_str(), &status) == 0 && S_ISCHR(status.st_mode);
}

bool write_all(int fd, std::string_view contents) {
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const auto count = write(fd, contents.data() + offset, contents.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

bool save_state(std::string_view state) {
    const int directory = open(kStateDirectory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        report("cannot open state directory");
        return false;
    }
    if (!safe_state_directory(directory)) {
        close(directory);
        return false;
    }

    const std::string temporary = std::string(".") + kStateFile + ".tmp." +
                                  std::to_string(getpid());
    const int file = openat(directory, temporary.c_str(),
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (file < 0) {
        report("cannot create temporary state file");
        close(directory);
        return false;
    }

    bool success = write_all(file, std::string(state) + "\n") && fsync(file) == 0;
    const int saved_errno = errno;
    if (close(file) != 0) {
        success = false;
    }
    if (success && renameat(directory, temporary.c_str(), directory, kStateFile) != 0) {
        success = false;
    }
    if (success && fsync(directory) != 0) {
        success = false;
    }
    if (!success) {
        unlinkat(directory, temporary.c_str(), 0);
        errno = saved_errno;
        report("cannot persist setup state");
    }
    close(directory);
    return success;
}

bool read_state(std::string& state, bool& exists) {
    exists = false;
    const int directory = open(kStateDirectory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 && errno != ENOENT) {
        report("cannot open state directory");
        return false;
    }
    if (directory < 0) {
        return true;
    }
    if (!safe_state_directory(directory)) {
        close(directory);
        return false;
    }

    const int file = openat(directory, kStateFile, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    const int open_errno = errno;
    close(directory);
    if (file < 0) {
        if (open_errno == ENOENT) {
            return true;
        }
        report("cannot open setup state file");
        return false;
    }

    struct stat status {};
    if (fstat(file, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != 0 || (status.st_mode & 0077) != 0 || status.st_size > 256) {
        close(file);
        report("setup state file has unsafe ownership, permissions, or size");
        return false;
    }
    std::array<char, 257> buffer {};
    std::size_t total = 0;
    bool read_failed = false;
    while (true) {
        const auto count = read(file, buffer.data() + total, buffer.size() - total);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            read_failed = true;
            break;
        }
        if (count == 0) {
            break;
        }
        total += static_cast<std::size_t>(count);
        if (total == buffer.size()) {
            break;
        }
    }
    const int read_errno = errno;
    close(file);
    if (read_failed) {
        errno = read_errno;
        report("cannot read setup state file");
        return false;
    }
    if (total >= buffer.size()) {
        report("setup state file is too large");
        return false;
    }
    state.assign(buffer.data(), total);
    while (!state.empty() && (state.back() == '\n' || state.back() == '\r')) {
        state.pop_back();
    }
    if (state.empty() || state.find('\n') != std::string::npos ||
        state.find('\r') != std::string::npos) {
        report("setup state file is malformed");
        return false;
    }
    exists = true;
    return true;
}

bool read_username(int console, std::string& username) {
    constexpr char prompt[] = "New username (45-second timeout): ";
    if (!write_all(console, prompt)) {
        report("cannot write to the selected console");
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(kUsernameTimeoutSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        struct pollfd descriptor { console, POLLIN, 0 };
        const int ready = poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            report("cannot read from the selected console");
            return false;
        }
        if (ready == 0) {
            break;
        }
        char character = '\0';
        const auto count = read(console, &character, 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            report("console closed while reading the username");
            return false;
        }
        if (character == '\n' || character == '\r') {
            write_all(console, "\n");
            return true;
        }
        if (username.size() < 33) {
            username.push_back(character);
        }
    }
    write_all(console, "\nNo username entered; continuing to the normal login prompt.\n");
    username.clear();
    return true;
}

int lookup_user(const std::string& username, struct passwd& result,
                std::vector<char>& storage) {
    storage.resize(16384);
    struct passwd* entry = nullptr;
    const int code = getpwnam_r(username.c_str(), &result, storage.data(),
                                storage.size(), &entry);
    if (code != 0) {
        errno = code;
        report("cannot query the local account database");
        return -1;
    }
    return entry != nullptr ? 1 : 0;
}

bool run_program(const char* path, std::vector<char*>& arguments, int console = -1) {
    const pid_t child = fork();
    if (child < 0) {
        report("cannot start account-management command");
        return false;
    }
    if (child == 0) {
        if (console >= 0) {
            if (dup2(console, STDIN_FILENO) < 0 || dup2(console, STDOUT_FILENO) < 0 ||
                dup2(console, STDERR_FILENO) < 0) {
                dprintf(STDERR_FILENO, "ExamOS development account setup: "
                        "cannot connect password command to the console: %s\n",
                        std::strerror(errno));
                _exit(126);
            }
        }
        execv(path, arguments.data());
        dprintf(STDERR_FILENO, "ExamOS development account setup: "
                "cannot execute %s: %s\n", path, std::strerror(errno));
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            report("cannot wait for account-management command");
            return false;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        report("account-management command exited unsuccessfully");
        return false;
    }
    return true;
}

bool expected_development_account(const std::string& username) {
    struct passwd account {};
    std::vector<char> storage;
    if (lookup_user(username, account, storage) != 1) {
        report("expected account does not exist");
        return false;
    }
    const std::string expected_home = "/home/" + username;
    if (account.pw_uid < 1000 || account.pw_dir == nullptr ||
        expected_home != account.pw_dir || account.pw_shell == nullptr ||
        std::strcmp(account.pw_shell, "/bin/bash") != 0 ||
        account.pw_gid == 0) {
        report("account does not match the expected development-account properties");
        return false;
    }

    struct group* primary = getgrgid(account.pw_gid);
    if (primary == nullptr || primary->gr_name == nullptr ||
        username != primary->gr_name) {
        report("account does not have its expected private primary group");
        return false;
    }

    int group_count = 16;
    std::vector<gid_t> groups(static_cast<std::size_t>(group_count));
    if (getgrouplist(username.c_str(), account.pw_gid, groups.data(), &group_count) < 0) {
        groups.resize(static_cast<std::size_t>(group_count));
        if (getgrouplist(username.c_str(), account.pw_gid, groups.data(), &group_count) < 0) {
            report("cannot query account group membership");
            return false;
        }
    }
    struct group* sudo_group = getgrnam("sudo");
    if (sudo_group == nullptr) {
        report("required development sudo group does not exist");
        return false;
    }
    for (int index = 0; index < group_count; ++index) {
        if (groups[static_cast<std::size_t>(index)] == sudo_group->gr_gid) {
            return true;
        }
    }
    report("account is not in the development sudo group");
    return false;
}

int password_is_set(const std::string& username) {
    struct spwd shadow_entry {};
    std::array<char, 16384> storage {};
    struct spwd* result = nullptr;
    const int code = getspnam_r(username.c_str(), &shadow_entry, storage.data(),
                                storage.size(), &result);
    if (code != 0 || result == nullptr || result->sp_pwdp == nullptr) {
        report("cannot query the account password state");
        return -1;
    }
    const std::string_view hash(result->sp_pwdp);
    return !hash.empty() && hash.front() != '!' && hash.front() != '*' ? 1 : 0;
}

int setup(const char* console_path) {
    if (!valid_console_path(console_path)) {
        report("a valid console device is required");
        return 1;
    }
    const int console = open(console_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (console < 0 || !isatty(console)) {
        report("cannot open the selected console as a terminal");
        if (console >= 0) {
            close(console);
        }
        return 1;
    }

    std::string state;
    bool state_exists = false;
    if (!read_state(state, state_exists)) {
        close(console);
        return 1;
    }
    if (state_exists && state.rfind("complete:", 0) == 0) {
        close(console);
        return valid_username(std::string_view(state).substr(9)) ? 0 : 1;
    }

    std::string username;
    if (state_exists) {
        if (state.rfind("pending:", 0) != 0) {
            report("setup state is invalid");
            close(console);
            return 1;
        }
        username = state.substr(8);
        if (!valid_username(username)) {
            report("pending account name is invalid");
            close(console);
            return 1;
        }
        dprintf(console, "\nResuming account setup for %s after an interrupted first boot.\n",
                username.c_str());
    } else {
        write_all(console, "\nExamOS development first-boot setup\n"
                           "Create a local console account. The password will not be displayed.\n");
        if (!read_username(console, username)) {
            close(console);
            return 1;
        }
        if (username.empty()) {
            close(console);
            return 0;
        }
        if (!valid_username(username)) {
            write_all(console, "Invalid username. Use 1-32 lowercase letters, digits, underscores or hyphens; do not use root.\n");
            close(console);
            return 1;
        }

        struct passwd account {};
        std::vector<char> storage;
        const int lookup_result = lookup_user(username, account, storage);
        if (lookup_result == 1) {
            write_all(console, "That account already exists; refusing to modify it.\n");
            close(console);
            return 1;
        }
        if (lookup_result < 0) {
            close(console);
            return 1;
        }

        if (mkdir(kStateDirectory, 0755) != 0 && errno != EEXIST) {
            report("cannot create setup state directory");
            close(console);
            return 1;
        }
        if (!save_state("pending:" + username)) {
            close(console);
            return 1;
        }
    }

    std::vector<char*> useradd_arguments {
        const_cast<char*>("useradd"), const_cast<char*>("--create-home"),
        const_cast<char*>("--user-group"), const_cast<char*>("--shell"),
        const_cast<char*>("/bin/bash"), const_cast<char*>("--groups"),
        const_cast<char*>("sudo"), const_cast<char*>("--"),
        const_cast<char*>(username.c_str()), nullptr
    };
    struct passwd account {};
    std::vector<char> storage;
    const int lookup_result = lookup_user(username, account, storage);
    if (lookup_result == 0) {
        if (!run_program("/usr/sbin/useradd", useradd_arguments)) {
            report("account creation failed; setup will retry on the next boot");
            close(console);
            return 1;
        }
    } else if (lookup_result < 0) {
        close(console);
        return 1;
    }
    if (!expected_development_account(username)) {
        close(console);
        return 1;
    }

    const int password_status = password_is_set(username);
    if (password_status < 0) {
        close(console);
        return 1;
    }
    if (password_status == 1) {
        if (!save_state("complete:" + username)) {
            close(console);
            return 1;
        }
        dprintf(console, "Development account %s is already configured.\n",
                username.c_str());
        close(console);
        return 0;
    }

    dprintf(console, "\nSet a password for %s. Enter it twice when prompted.\n",
            username.c_str());
    std::vector<char*> passwd_arguments {
        const_cast<char*>("passwd"), const_cast<char*>(username.c_str()), nullptr
    };
    if (!run_program("/usr/bin/passwd", passwd_arguments, console) ||
        password_is_set(username) != 1) {
        write_all(console, "\nPassword setup failed; setup will resume on the next boot.\n");
        close(console);
        return 1;
    }
    if (!save_state("complete:" + username)) {
        close(console);
        return 1;
    }
    dprintf(console, "\nDevelopment account %s is ready. Log in with the password you just created.\n",
            username.c_str());
    close(console);
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (geteuid() != 0) {
        report("must run as root");
        return 1;
    }
    if (argc != 2) {
        report("usage: examos-dev-console-setup /dev/ttyS0");
        return 1;
    }
    return setup(argv[1]);
}
