#pragma once

#include <string>
#include <vector>

// Keystore access. The verifier only reads (find_device); the provisioning
// tool is the only writer. The schema is described in one place -- see
// db/schema.sql.

struct Device {
    std::string id;
    std::string key;
    int status = 0;         // 1 = active, 0 = revoked. Defaults to revoked, so
                            // a Device nobody filled in never counts as active.
    std::string note = "OK";
    std::string created;    // UTC, "YYYY-MM-DD HH:MM:SS". Empty on old rows.
};

// Device IDs are Crockford Base32 (no I, L, O, U), 4 to 8 characters. New
// devices get 4 today; the range leaves room to lengthen them later without a
// migration.
constexpr int DEVICE_ID_MIN = 4;
constexpr int DEVICE_ID_MAX = 8;

// True if `id` is a well-formed device ID. Every entry point checks this before
// the ID reaches SQL or a log line -- never rely on the caller having done it.
bool valid_device_id(const std::string& id);

// Path to the keystore database, in precedence order:
//   1. $XAUTH_DB, if set and non-empty  -- how deployments should set it
//   2. XAUTH_DB_DEFAULT, baked in at compile time by the Makefile as an
//      absolute path, so a dev build runs from any working directory
//   3. "db/auth", relative to the cwd -- last resort
std::string db_path();

// Outcome of a keystore lookup. Error is deliberately separate from NotFound:
// an unreachable keystore is an operator problem and should be shouted about,
// while a missing device is a normal, expected auth failure.
//
// Callers must still treat Error as a failure to authenticate -- the
// distinction is for logs, and must never reach the end user, who sees the
// same generic rejection either way.
enum class Lookup { Found, NotFound, Error };

// Looks up a device by ID. `out` is only written on Found. A revoked device is
// still Found, with status == 0 -- what to do about that is the caller's job.
// A malformed ID is NotFound without touching the database.
Lookup find_device(const std::string& id, Device& out);

// ---- Writers. Provisioning tool only. ----------------------------------------

// Brings an existing keystore up to the current schema (adds columns that
// older versions lacked). Idempotent. Returns false on any sqlite error.
bool migrate_keystore();

// Inserts a newly provisioned device. Returns false on any sqlite error,
// including an ID collision against the primary key.
bool add_device(const Device& device);

// Sets Status for an existing device. Returns Lookup::NotFound if no row
// matched, so "revoke a typo" is reported instead of silently succeeding.
Lookup set_device_status(const std::string& id, int status);

// Replaces the admin-facing label.
Lookup set_device_note(const std::string& id, const std::string& note);

// Every device, without key material. Returns false on any sqlite error.
bool list_devices(std::vector<Device>& out);
