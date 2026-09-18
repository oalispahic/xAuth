#include "keystore.hpp"

#include <sqlite3.h>
#include <cstdlib>
#include <cstring>
#include <iostream>

#ifndef XAUTH_DB_DEFAULT
#define XAUTH_DB_DEFAULT "db/auth"
#endif

namespace {

// Crockford Base32 without the check symbols: 0-9 and A-Z minus I, L, O, U.
bool crockford_char(char c) {
    if (c >= '0' && c <= '9') return true;
    if (c < 'A' || c > 'Z') return false;
    return c != 'I' && c != 'L' && c != 'O' && c != 'U';
}

// Owns a connection so every early return closes it.
struct Db {
    sqlite3* handle = nullptr;
    ~Db() { if (handle) sqlite3_close(handle); }
};

bool open_db(Db& db, int flags) {
    int rc = sqlite3_open_v2(db_path().c_str(), &db.handle, flags, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "keystore: cannot open " << db_path() << ": "
                  << (db.handle ? sqlite3_errmsg(db.handle) : sqlite3_errstr(rc)) << std::endl;
        return false;
    }
    // Another writer (a provisioning run) can hold the lock briefly.
    sqlite3_busy_timeout(db.handle, 1000);
    return true;
}

// Runs a single-row UPDATE bound to (value, id). Reports NotFound when the ID
// matched nothing.
Lookup update_one(const char* sql, const std::string& id,
                  const std::string* text_value, int int_value) {
    if (!valid_device_id(id)) return Lookup::NotFound;
    Db db;
    if (!open_db(db, SQLITE_OPEN_READWRITE)) return Lookup::Error;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.handle, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "keystore: prepare failed: " << sqlite3_errmsg(db.handle) << std::endl;
        return Lookup::Error;
    }
    if (text_value) sqlite3_bind_text(stmt, 1, text_value->c_str(), -1, SQLITE_TRANSIENT);
    else            sqlite3_bind_int(stmt, 1, int_value);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "keystore: update failed: " << sqlite3_errmsg(db.handle) << std::endl;
        return Lookup::Error;
    }
    return sqlite3_changes(db.handle) > 0 ? Lookup::Found : Lookup::NotFound;
}

std::string column_text(sqlite3_stmt* stmt, int col) {
    const unsigned char* v = sqlite3_column_text(stmt, col);
    return v ? std::string(reinterpret_cast<const char*>(v)) : std::string();
}

}  // namespace

bool valid_device_id(const std::string& id) {
    if (id.size() < DEVICE_ID_MIN || id.size() > DEVICE_ID_MAX) return false;
    for (char c : id) {
        if (!crockford_char(c)) return false;
    }
    return true;
}

std::string db_path() {
    const char* env = std::getenv("XAUTH_DB");
    if (env && *env) return std::string(env);
    return std::string(XAUTH_DB_DEFAULT);
}

Lookup find_device(const std::string& id, Device& out) {
    // Before anything else: a malformed ID never reaches SQL, a path, or a log.
    if (!valid_device_id(id)) return Lookup::NotFound;

    Db db;
    // SQLITE_OPEN_READONLY: the verifier has no business writing to the
    // keystore, so don't hand it a writable handle it could be tricked into using.
    if (!open_db(db, SQLITE_OPEN_READONLY)) return Lookup::Error;

    const char* sql = "SELECT Key, Status, Note FROM secure_key_data WHERE ID = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.handle, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "keystore: failed to prepare statement: " << sqlite3_errmsg(db.handle) << std::endl;
        return Lookup::Error;
    }

    // SQLITE_TRANSIENT: sqlite copies the text instead of holding a pointer into
    // a string the caller may destroy before the statement is stepped.
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    Lookup result = Lookup::NotFound;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* key = sqlite3_column_text(stmt, 0);
        if (key != nullptr) {
            out.id     = id;
            out.key    = std::string(reinterpret_cast<const char*>(key));
            out.status = sqlite3_column_int(stmt, 1);
            out.note   = column_text(stmt, 2);
            result = Lookup::Found;
        }
    } else if (rc != SQLITE_DONE) {
        std::cerr << "keystore: lookup failed: " << sqlite3_errmsg(db.handle) << std::endl;
        result = Lookup::Error;
    }

    sqlite3_finalize(stmt);
    return result;
}

bool migrate_keystore() {
    Db db;
    if (!open_db(db, SQLITE_OPEN_READWRITE)) return false;

    // Keystores made before the Created column existed. ALTER TABLE cannot add
    // a column with a non-constant default, so old rows get NULL and the
    // provisioning tool writes the timestamp explicitly from now on.
    bool has_created = false;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.handle, "PRAGMA table_info(secure_key_data)", -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "keystore: cannot read schema: " << sqlite3_errmsg(db.handle) << std::endl;
        return false;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (column_text(stmt, 1) == "Created") has_created = true;
    }
    sqlite3_finalize(stmt);

    if (!has_created) {
        char* err = nullptr;
        if (sqlite3_exec(db.handle, "ALTER TABLE secure_key_data ADD COLUMN Created TEXT",
                         nullptr, nullptr, &err) != SQLITE_OK) {
            std::cerr << "keystore: migration failed: " << (err ? err : "?") << std::endl;
            sqlite3_free(err);
            return false;
        }
    }
    return true;
}

bool add_device(const Device& device) {
    if (!valid_device_id(device.id)) {
        std::cerr << "keystore: refusing to insert a malformed device ID" << std::endl;
        return false;
    }
    Db db;
    if (!open_db(db, SQLITE_OPEN_READWRITE)) return false;

    // Bound parameters, not string concatenation. Note is a human-supplied label.
    const char* sql = "INSERT INTO secure_key_data (ID, Key, Status, Note, Created) "
                      "VALUES (?, ?, ?, ?, datetime('now'))";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.handle, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "keystore: prepare failed: " << sqlite3_errmsg(db.handle) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, device.id.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, device.key.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, device.status);
    sqlite3_bind_text(stmt, 4, device.note.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "keystore: insert failed: " << sqlite3_errmsg(db.handle) << std::endl;
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

Lookup set_device_status(const std::string& id, int status) {
    return update_one("UPDATE secure_key_data SET Status = ? WHERE ID = ?", id, nullptr, status);
}

Lookup set_device_note(const std::string& id, const std::string& note) {
    return update_one("UPDATE secure_key_data SET Note = ? WHERE ID = ?", id, &note, 0);
}

bool list_devices(std::vector<Device>& out) {
    Db db;
    if (!open_db(db, SQLITE_OPEN_READONLY)) return false;

    // Key is deliberately not selected: listing must never put secrets on a terminal.
    const char* sql = "SELECT ID, Status, Note, COALESCE(Created, '') FROM secure_key_data ORDER BY ID";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.handle, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "keystore: prepare failed: " << sqlite3_errmsg(db.handle) << std::endl;
        return false;
    }
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        Device d;
        d.id      = column_text(stmt, 0);
        d.status  = sqlite3_column_int(stmt, 1);
        d.note    = column_text(stmt, 2);
        d.created = column_text(stmt, 3);
        out.push_back(d);
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}
