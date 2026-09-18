// xAuth admin daemon: the only process that writes the keystore at runtime.
//
// auth-web's admin dashboard talks to it over a Unix socket, one request per
// connection, so the web tier still never opens the keystore itself:
//
//   LIST\n                 ->  DEVICE <id> <status> <created> <label>\n ... END\n
//   ADD <label>\n          ->  OK <id> <key>\n        (the only time a key leaves)
//   REVOKE <id>\n          ->  OK\n | NO\n
//   ACTIVATE <id>\n        ->  OK\n | NO\n
//   LABEL <id> <label>\n   ->  OK\n | NO\n
//   anything else          ->  ERR\n
//
// ADD returns the key once, for the firmware header of the keychain being
// provisioned. Nothing else ever reads keys back out. The verifier daemon is
// a separate, read-only process; this one exists so the read-only one can
// stay that way.
//
//   usage: xauth-admin --socket PATH [--mode 0660] [--allow-uid UID]

#include "../core/keystore.hpp"
#include "../core/keygen.hpp"

#include <openssl/crypto.h>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>
#include <cerrno>
#include <cstring>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr size_t MAX_REQUEST = 128;
constexpr int    IO_TIMEOUT_SEC = 5;

char socket_path[sizeof(sockaddr_un::sun_path)];

void on_signal(int) {
    unlink(socket_path);
    _exit(0);
}

std::string ok_no(Lookup r) {
    return r == Lookup::Found ? "OK\n" : (r == Lookup::NotFound ? "NO\n" : "ERR\n");
}

std::string handle_add(const std::string& label) {
    if (!valid_label(label)) return "ERR\n";
    Device d;
    d.status = 1;
    d.note = label;
    d.key = generate_key();

    std::string reply = "ERR\n";
    for (int attempt = 0; attempt < 16; attempt++) {
        d.id = generate_device_id(DEVICE_ID_MIN);
        Device existing;
        Lookup l = find_device(d.id, existing);
        if (!existing.key.empty()) OPENSSL_cleanse(&existing.key[0], existing.key.size());
        if (l == Lookup::Error) break;
        if (l == Lookup::NotFound && add_device(d)) {
            reply = "OK " + d.id + " " + d.key + "\n";
            break;
        }
    }
    OPENSSL_cleanse(&d.key[0], d.key.size());
    return reply;
}

std::string handle_list() {
    std::vector<Device> devices;
    if (!list_devices(devices)) return "ERR\n";
    std::string out;
    for (const Device& d : devices) {
        out += "DEVICE " + d.id + " " + (d.status == 1 ? "active" : "revoked") + " " +
               (d.created.empty() ? "-" : d.created) + " " + d.note + "\n";
    }
    return out + "END\n";
}

std::string handle_request(const std::string& line) {
    size_t sp = line.find(' ');
    std::string cmd = line.substr(0, sp);
    std::string rest = sp == std::string::npos ? "" : line.substr(sp + 1);

    if (cmd == "LIST" && rest.empty()) return handle_list();
    if (cmd == "ADD") return handle_add(rest);
    if (cmd == "REVOKE" && !rest.empty()) return ok_no(set_device_status(rest, 0));
    if (cmd == "ACTIVATE" && !rest.empty()) return ok_no(set_device_status(rest, 1));
    if (cmd == "LABEL") {
        size_t sp2 = rest.find(' ');
        if (sp2 == std::string::npos) return "ERR\n";
        std::string label = rest.substr(sp2 + 1);
        if (!valid_label(label)) return "ERR\n";
        return ok_no(set_device_note(rest.substr(0, sp2), label));
    }
    return "ERR\n";
}

// Created timestamps contain a space ("2026-09-18 12:00:00"); LIST replaces
// it so every field stays single-token for the client.
std::string single_token_dates(std::string s) {
    size_t pos = 0;
    while ((pos = s.find("DEVICE ", pos)) != std::string::npos) {
        // id status created(date time) label...: the created field is the
        // third token; join its two halves with 'T'.
        size_t a = s.find(' ', pos + 7);           // after id
        size_t b = a == std::string::npos ? a : s.find(' ', a + 1);   // after status
        if (b != std::string::npos && b + 11 < s.size() && s[b + 11] == ' ' && s[b + 1] != '-') {
            s[b + 11] = 'T';
        }
        pos = s.find('\n', pos);
        if (pos == std::string::npos) break;
    }
    return s;
}

bool read_line(int fd, std::string& out) {
    char buf[MAX_REQUEST + 1];
    size_t len = 0;
    while (len < sizeof buf) {
        ssize_t r = read(fd, buf + len, sizeof buf - len);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        for (ssize_t i = 0; i < r; i++) {
            if (buf[len + i] == '\n') {
                out.assign(buf, len + i);
                return true;
            }
        }
        len += r;
    }
    return false;
}

void write_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t w = write(fd, s.data() + off, s.size() - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        off += w;
    }
}

bool peer_allowed(int fd, long allow_uid) {
    if (allow_uid < 0) return true;
    uid_t uid;
#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    uid = cred.uid;
#else
    gid_t gid;
    if (getpeereid(fd, &uid, &gid) != 0) return false;
#endif
    return static_cast<long>(uid) == allow_uid;
}

int usage() {
    std::cerr << "usage: xauth-admin --socket PATH [--mode 0660] [--allow-uid UID]" << std::endl;
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string path;
    mode_t mode = 0660;
    long allow_uid = -1;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (i + 1 >= argc) return usage();
        std::string val = argv[++i];
        try {
            if (arg == "--socket") path = val;
            else if (arg == "--mode") mode = static_cast<mode_t>(std::stoul(val, nullptr, 8));
            else if (arg == "--allow-uid") allow_uid = std::stol(val);
            else return usage();
        } catch (const std::exception&) { return usage(); }
    }
    if (path.empty()) return usage();
    if (path.size() >= sizeof socket_path) {
        std::cerr << "xauth-admin: socket path too long (max " << sizeof socket_path - 1 << ")" << std::endl;
        return 2;
    }
    std::strncpy(socket_path, path.c_str(), sizeof socket_path - 1);

    struct rlimit none = { 0, 0 };
    setrlimit(RLIMIT_CORE, &none);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    if (!migrate_keystore()) {
        std::cerr << "xauth-admin: keystore " << db_path() << " is not writable" << std::endl;
        return 1;
    }

    struct stat st;
    if (lstat(socket_path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            std::cerr << "xauth-admin: " << path << " exists and is not a socket" << std::endl;
            return 1;
        }
        unlink(socket_path);
    }

    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) { perror("xauth-admin: socket"); return 1; }
    fcntl(listener, F_SETFD, FD_CLOEXEC);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path, sizeof addr.sun_path - 1);
    mode_t old_umask = umask(0177);
    int rc = bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    umask(old_umask);
    if (rc != 0) { perror("xauth-admin: bind"); return 1; }
    if (chmod(socket_path, mode & 0770) != 0) { perror("xauth-admin: chmod"); return 1; }
    if (listen(listener, 16) != 0) { perror("xauth-admin: listen"); return 1; }

    std::cerr << "xauth-admin: listening on " << path << ", keystore " << db_path() << std::endl;

    // One request at a time: admin actions are rare, and serialising them
    // means two concurrent ADDs cannot race on an ID.
    for (;;) {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            perror("xauth-admin: accept");
            continue;
        }
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        struct timeval tv = { IO_TIMEOUT_SEC, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        std::string line;
        if (!peer_allowed(fd, allow_uid)) {
            std::cerr << "xauth-admin: refused a connection from a disallowed uid" << std::endl;
        } else if (read_line(fd, line)) {
            std::string reply = single_token_dates(handle_request(line));
            write_all(fd, reply);
            OPENSSL_cleanse(&reply[0], reply.size());
        } else {
            write_all(fd, "ERR\n");
        }
        shutdown(fd, SHUT_WR);
        char sink[256];
        ssize_t r;
        size_t drained = 0;
        while (drained < 4096 && ((r = read(fd, sink, sizeof sink)) > 0 || (r < 0 && errno == EINTR))) {
            if (r > 0) drained += r;
        }
        close(fd);
    }
}
