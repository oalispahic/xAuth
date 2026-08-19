#include <iostream>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <cstdio>
#include <sqlite3.h>
#include <algorithm>

struct User{
    std::string user_id;
    std::string key;
    int status = 1;
    std::string note = "OK";
};

std::string generate_device_id(int length = 4) {
    static const char alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // 32 chars
    std::vector<unsigned char> buf(length);

    if (RAND_bytes(buf.data(), length) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    std::string id;
    for (unsigned char b : buf) {
        id += alphabet[b % 32];
    }
    return id;
}

std::string generate_key(){
    FILE *fp = popen("openssl rand -hex 64","r");
    std::string key;
    char buf[128];
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        key += buf;
    }
    pclose(fp);
    key.erase(std::remove(key.begin(), key.end(), '\n'), key.end());
    key.erase(std::remove(key.begin(), key.end(), '\r'), key.end());
    return key;
}

User generate_user(){
    User user;
    user.user_id = generate_device_id();
    user.key = generate_key();
    return user;
}

void add_new_user(User user){
    sqlite3 *db;
    int rc = sqlite3_open("../xAuth_db/auth",&db);
    if(rc != SQLITE_OK){
        std::cerr<<"Database not found or bad path"<<std::endl<<sqlite3_errmsg(db)<<std::endl;
        sqlite3_close(db);
        return;
    }
    const std::string sql_string = "INSERT INTO secure_key_data (ID, Key, Status, Note) VALUES ('"
                                   + user.user_id + "', '"
                                   + user.key + "', "
                                   + std::to_string(user.status) + ", '"
                                   + user.note + "');";
    const char *sql = sql_string.c_str();
    rc = sqlite3_exec(db,sql,nullptr,nullptr,nullptr);
    sqlite3_close(db);
}

int main(){

   User new_user = generate_user();
    std::cout<<"Generated user: "<<new_user.user_id<<std::endl;
    add_new_user(new_user);

}