#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <sqlite3.h>

#define OTP_SIZE 8
std::string HASH_KEY;
std::string USER_ID;

std::vector<unsigned char> hmac_sha256(const std::string& key,
                                        const unsigned char* msg, size_t msg_len) {
    unsigned char* digest;
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);

    digest = HMAC(EVP_sha256(),
                  key.data(), key.size(),
                  msg, msg_len,
                  out.data(), &len);

    if (!digest) throw std::runtime_error("HMAC failed");
    out.resize(len);
    return out;
}

uint32_t dynamic_truncate(const std::vector<unsigned char>& hmac, int digits) {
    int offset = hmac.back() & 0x0F;

    uint32_t bin_code = ((hmac[offset]     & 0x7F) << 24) |
                         ((hmac[offset + 1] & 0xFF) << 16) |
                         ((hmac[offset + 2] & 0xFF) << 8)  |
                          (hmac[offset + 3] & 0xFF);

    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;

    return bin_code % mod;
}

uint32_t totp(const std::string& key, time_t now, int step_seconds = 90, int digits = OTP_SIZE) {
    uint64_t counter = static_cast<uint64_t>(now) / step_seconds;

    // counter must be big-endian 8 bytes
    unsigned char counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    auto mac = hmac_sha256(key, counter_bytes, 8);
    return dynamic_truncate(mac, digits);
}

void formated_print(uint32_t code){

    std::cout<<"Uncut code: "<< code << std::endl;

    int first_four = code / 10000;
    int second_four = code % 10000;
    std::cout<<"Code: "<<first_four<<" - "<<second_four;

    std::cout<<std::endl;
}

std::string pad_and_convert(uint32_t code) {
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(OTP_SIZE) << code;
    std::string computed_code = oss.str();
    return computed_code;
}

void clean_trash(std::string &str, int size=OTP_SIZE) {
    std::string cleaned;
    for(char c : str) {
        if (std::isdigit(c)) {
            cleaned += c;
        }
    }
    str = cleaned;
    std::cout<<"CLEANED "<< cleaned << std::endl;
}

int verify(const std::string& code, const std::string& otp_code) {
    if(otp_code == code) {
        std::cout<<"OK"<<std::endl;
        return 0;
    } else {
        std::cout<<"Bad code!"<<std::endl;
        return 1;
    }
}

void find_userkey(const std::string& user_id){
    sqlite3 *db;
    int rc = sqlite3_open("../xAuth_db/auth", &db);
    if(rc != SQLITE_OK){
        std::cerr<<"Db not found or bad path"<<std::endl<<sqlite3_errmsg(db)<<std::endl;
        sqlite3_close(db);
    }
    const char* sql = "SELECT Key FROM secure_key_data WHERE ID = ?";
    sqlite3_stmt *stmt = nullptr;
     rc = sqlite3_prepare_v2(db,sql,-1,&stmt,nullptr);
    if(rc != SQLITE_OK){
        std::cerr<<"Failed to prepare statement: "<<sqlite3_errmsg(db)<<std::endl;
        sqlite3_close(db);
    }
    sqlite3_bind_text(stmt,1,USER_ID.c_str(),-1,nullptr);

    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        const unsigned char* key = sqlite3_column_text(stmt,0);
        if(key != nullptr){
            HASH_KEY = std::string(reinterpret_cast<const char*>(key));
    }
    else{
        std::cerr<<"User not found"<<std::endl;
    }
    return;
}
}

void input_userID(){
    std::string user_id;
    std::cout<< "User ID?" << std::endl;
    std::getline(std::cin, user_id);
    USER_ID = user_id;
}

int main() {
    
    input_userID();
    find_userkey(USER_ID);

    uint32_t code = totp(HASH_KEY, time(nullptr));


    std::string otp_code = pad_and_convert(code);
    std::string check_code;

    std::getline(std::cin, check_code);
    clean_trash(check_code);

    verify(check_code, otp_code);
    

}
