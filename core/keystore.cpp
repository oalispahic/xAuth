#include "keystore.hpp"

#include <sqlite3.h>
#include <cstdlib>
#include <iostream>

std::string db_path() {
    const char* env = std::getenv("XAUTH_DB");
    return env ? std::string(env) : std::string("db/auth");
}

bool find_device(const std::string& id, Device& out) {
    sqlite3* db = nullptr;
    // SQLITE_OPEN_READONLY: the verifier has no business writing to the
    // keystore, so don't hand it a writable handle it could be tricked into using.
    int rc = sqlite3_open_v2(db_path().c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Db not found or bad path" << std::endl << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;   // the original fell through here and used a dead handle
    }

    const char* sql = "SELECT Key, Status, Note FROM secure_key_data WHERE ID = ?";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;   // likewise -- this used to reach bind_text with stmt == nullptr
    }

    // SQLITE_TRANSIENT: sqlite copies the text instead of holding a pointer into
    // a string the caller may destroy before the statement is stepped.
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* key = sqlite3_column_text(stmt, 0);
        if (key != nullptr) {
            out.id     = id;
            out.key    = std::string(reinterpret_cast<const char*>(key));
            out.status = sqlite3_column_int(stmt, 1);
            const unsigned char* note = sqlite3_column_text(stmt, 2);
            out.note   = note ? std::string(reinterpret_cast<const char*>(note)) : "";
            found = true;
        }
    }

    sqlite3_finalize(stmt);   // neither of these ran in the original
    sqlite3_close(db);
    return found;
}

bool add_device(const Device& device) {
    sqlite3* db = nullptr;
    int rc = sqlite3_open_v2(db_path().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Database not found or bad path" << std::endl << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }

    // Bound parameters, not string concatenation. Nothing here is attacker-controlled
    // today, but Note is exactly the field that grows a human-supplied label later.
    const char* sql = "INSERT INTO secure_key_data (ID, Key, Status, Note) VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, device.id.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, device.key.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, device.status);
    sqlite3_bind_text(stmt, 4, device.note.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE;
}
