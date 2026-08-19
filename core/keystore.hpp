#pragma once

#include <string>

// Keystore access. Both the verifier (read) and the provisioning tool (write)
// go through here, so the schema is described in exactly one place -- see
// db/schema.sql.

struct Device {
    std::string id;
    std::string key;
    int status = 1;         // 1 = active, 0 = revoked
    std::string note = "OK";
};

// Path to the keystore database. Reads XAUTH_DB if set, otherwise falls back to
// "db/auth" relative to the working directory. The original code hardcoded
// "../xAuth_db/auth", which broke as soon as the binary ran from anywhere but
// its own build directory -- set XAUTH_DB explicitly for anything long-running.
std::string db_path();

// Looks up a device by ID. Returns true only if the row exists and was read
// cleanly; `out` is untouched otherwise. A revoked device still returns true
// with status == 0 -- deciding what to do about that is the caller's job.
bool find_device(const std::string& id, Device& out);

// Inserts a newly provisioned device. Returns false on any sqlite error,
// including an ID collision against the primary key.
bool add_device(const Device& device);
