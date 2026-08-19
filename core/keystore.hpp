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

// Path to the keystore database, in precedence order:
//   1. $XAUTH_DB, if set and non-empty  -- how deployments should set it
//   2. XAUTH_DB_DEFAULT, baked in at compile time by the Makefile as an
//      absolute path, so a dev build runs from any working directory
//   3. "db/auth", relative to the cwd -- last resort
//
// Both earlier versions of this were cwd-relative ("../xAuth_db/auth", then
// "db/auth"), which meant the binary only worked when launched from one
// specific directory and failed in a way that looked like a rejected code.
std::string db_path();

// Outcome of a keystore lookup. Error is deliberately separate from NotFound:
// an unreachable keystore is an operator problem and should be shouted about,
// while a missing device is a normal, expected auth failure.
//
// Callers must still treat Error as a failure to authenticate -- the
// distinction is for logs and exit codes, and must never reach the end user,
// who sees the same generic rejection either way.
enum class Lookup { Found, NotFound, Error };

// Looks up a device by ID. `out` is only written on Found. A revoked device is
// still Found, with status == 0 -- what to do about that is the caller's job.
Lookup find_device(const std::string& id, Device& out);

// Inserts a newly provisioned device. Returns false on any sqlite error,
// including an ID collision against the primary key.
bool add_device(const Device& device);
