#include "../core/otp.hpp"
#include "../core/keystore.hpp"

#include <openssl/crypto.h>   // CRYPTO_memcmp, OPENSSL_cleanse
#include <cctype>
#include <iostream>
#include <string>

// One-shot verifier: reads a device ID and a submitted code on stdin, exits 0
// if the code is valid and 1 if it is not.
//
// Exit code is the contract -- callers must test for 0, not for a specific
// nonzero value (a negative return is reported as 255 by POSIX wait()).
//
// Phase 2 turns this into a long-running daemon on a Unix socket and adds the
// counter -1/0/+1 drift window; see docs/development-plan.md.

void clean_trash(std::string &str) {
    std::string cleaned;
    for(char c : str) {
        // isdigit() is UB for negative char values, so widen through unsigned char.
        if (std::isdigit(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }
    str = cleaned;
}

int verify(const std::string& code, const std::string& otp_code) {
    // Constant-time: a byte-by-byte compare that returns early leaks how much of
    // the code was right, which is enough to walk a code out one digit at a time.
    // Comparing lengths first is fine -- the length is always OTP_SIZE and public.
    bool match = code.size() == otp_code.size() &&
                 CRYPTO_memcmp(code.data(), otp_code.data(), otp_code.size()) == 0;

    if(match) {
        std::cout<<"OK"<<std::endl;
        return 0;
    } else {
        std::cout<<"Bad code!"<<std::endl;
        return 1;
    }
}

std::string input_userID(){
    std::string user_id;
    std::cout<< "User ID?" << std::endl;
    std::getline(std::cin, user_id);
    return user_id;
}

int main() {

    std::string user_id = input_userID();

    Device device;
    bool found = find_device(user_id, device);

    std::string check_code;
    std::getline(std::cin, check_code);
    clean_trash(check_code);

    // Fail closed. The original left the key empty when the ID was unknown and
    // computed a code from it anyway -- an empty HMAC key is not a secret, so
    // anyone could compute the "valid" code for any ID that did not exist and
    // authenticate as it. Unknown ID and revoked device are both hard failures.
    //
    // Note this returns faster than a real verification does, which leaks which
    // IDs exist. Closing that needs the dummy-key path from architecture.md §6
    // -- a real random key held by the verifier, HMAC'd against so the timing
    // matches. That lands with the daemon in Phase 2.
    if (!found || device.status != 1) {
        std::cout<<"Bad code!"<<std::endl;
        return 1;
    }

    uint32_t code = totp(device.key, time(nullptr));
    std::string otp_code = pad_and_convert(code);

    int result = verify(check_code, otp_code);

    // Don't leave key material sitting in the process image any longer than needed.
    OPENSSL_cleanse(&device.key[0], device.key.size());
    OPENSSL_cleanse(&otp_code[0], otp_code.size());

    return result;   // the original discarded this and always exited 0
}
