#include "../../core/keystore.hpp"
#include "../../core/keygen.hpp"

#include <openssl/crypto.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// Keystore administration. The only writer of the keystore.
//
//   provision add [--label TEXT] [--id-length N] [--firmware-header PATH]
//   provision list
//   provision revoke ID
//   provision activate ID
//   provision label ID TEXT
//
// Secrets are never printed. `add` writes the key to the keystore and, with
// --firmware-header, to a 0600 header the keychain firmware is built from, so
// the key and the ID printed on the device always come from the same run.

namespace {

bool write_firmware_header(const std::string& path, const Device& d) {
    // 0600 from creation: the file holds a key and must never be world-readable,
    // not even for the instant between open() and chmod().
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        std::cerr << "cannot write " << path << ": " << std::strerror(errno) << std::endl;
        return false;
    }
    fchmod(fd, 0600);
    std::string body = firmware_header(d.id, d.key);
    bool ok = write(fd, body.data(), body.size()) == static_cast<ssize_t>(body.size());
    OPENSSL_cleanse(&body[0], body.size());
    close(fd);
    if (!ok) std::cerr << "short write to " << path << std::endl;
    return ok;
}

int usage() {
    std::cerr <<
        "usage:\n"
        "  provision add [--label TEXT] [--id-length N] [--firmware-header PATH]\n"
        "  provision list\n"
        "  provision revoke ID\n"
        "  provision activate ID\n"
        "  provision label ID TEXT\n";
    return 2;
}

int report(Lookup r, const std::string& id, const char* done) {
    if (r == Lookup::Found)    { std::cout << id << " " << done << std::endl; return 0; }
    if (r == Lookup::NotFound) { std::cerr << "no device " << id << std::endl; return 1; }
    return 1;   // Error, already logged by the keystore
}

int cmd_add(const std::vector<std::string>& args) {
    std::string label = "OK", header;
    int id_length = DEVICE_ID_MIN;
    for (size_t i = 0; i < args.size(); i++) {
        if (i + 1 >= args.size()) return usage();
        const std::string& v = args[++i];
        if (args[i - 1] == "--label") label = v;
        else if (args[i - 1] == "--firmware-header") header = v;
        else if (args[i - 1] == "--id-length") {
            try { id_length = std::stoi(v); } catch (...) { return usage(); }
        } else return usage();
    }
    if (!valid_label(label)) {
        std::cerr << "label must be 1-64 printable ASCII characters, no quotes or backslashes" << std::endl;
        return 2;
    }
    if (id_length < DEVICE_ID_MIN || id_length > DEVICE_ID_MAX) {
        std::cerr << "--id-length must be " << DEVICE_ID_MIN << "-" << DEVICE_ID_MAX << std::endl;
        return 2;
    }

    Device d;
    d.status = 1;
    d.note = label;
    d.key = generate_key();

    // Draw until the ID is free. With 4 chars there are ~1M IDs; a collision is
    // rare but must never overwrite or shadow an existing device.
    bool placed = false;
    for (int attempt = 0; attempt < 16 && !placed; attempt++) {
        d.id = generate_device_id(id_length);
        Device existing;
        Lookup l = find_device(d.id, existing);
        if (!existing.key.empty()) OPENSSL_cleanse(&existing.key[0], existing.key.size());
        if (l == Lookup::Error) break;
        if (l == Lookup::NotFound) placed = add_device(d);
    }

    int rc = 0;
    if (!placed) {
        std::cerr << "provisioning failed -- device not written" << std::endl;
        rc = 1;
    } else if (!header.empty() && !write_firmware_header(header, d)) {
        // The device exists but has no firmware. Revoke it so a half-provisioned
        // key is never live.
        set_device_status(d.id, 0);
        std::cerr << "device " << d.id << " written but header failed; revoked it" << std::endl;
        rc = 1;
    } else {
        std::cout << d.id << std::endl;
        if (!header.empty()) std::cerr << "firmware header written to " << header << std::endl;
    }
    OPENSSL_cleanse(&d.key[0], d.key.size());
    return rc;
}

int cmd_list() {
    std::vector<Device> devices;
    if (!list_devices(devices)) return 1;
    std::cout << std::left << std::setw(10) << "ID" << std::setw(10) << "STATUS"
              << std::setw(21) << "CREATED (UTC)" << "LABEL" << std::endl;
    for (const Device& d : devices) {
        std::cout << std::setw(10) << d.id
                  << std::setw(10) << (d.status == 1 ? "active" : "revoked")
                  << std::setw(21) << (d.created.empty() ? "-" : d.created)
                  << d.note << std::endl;
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage();
    std::string cmd = argv[1];
    std::vector<std::string> args(argv + 2, argv + argc);

    if (!migrate_keystore()) return 1;

    try {
        if (cmd == "add") return cmd_add(args);
        if (cmd == "list" && args.empty()) return cmd_list();
        if (cmd == "revoke" && args.size() == 1)
            return report(set_device_status(args[0], 0), args[0], "revoked");
        if (cmd == "activate" && args.size() == 1)
            return report(set_device_status(args[0], 1), args[0], "active");
        if (cmd == "label" && args.size() == 2) {
            if (!valid_label(args[1])) {
                std::cerr << "label must be 1-64 printable ASCII characters, no quotes or backslashes" << std::endl;
                return 2;
            }
            return report(set_device_note(args[0], args[1]), args[0], "relabelled");
        }
    } catch (const std::exception& e) {
        std::cerr << "provision: " << e.what() << std::endl;
        return 1;
    }
    return usage();
}
