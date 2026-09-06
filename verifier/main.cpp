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
    Lookup found = find_device(user_id, device);
    if (found == Lookup::Error) {
        // Error means the keystore itself could not be read -- not that the ID
        // is missing. Different problem, different 3am page. Operator-only, so
        // it goes to stderr and never changes what the caller sees.
        std::cerr<<"keystore: lookup failed for id "<<user_id<<std::endl;
        return 1;
    }

    std::string check_code;
    std::getline(std::cin, check_code);
    clean_trash(check_code);

    // Fail closed. Unknown ID and revoked device are one branch on purpose:
    // find_device() only writes to `device` on a hit, so a miss leaves the
    // defaults in place -- key "" and status 1 -- which sails straight past a
    // status-only check and gets HMAC'd with an empty key. An empty key is not
    // a secret, so that path lets anyone compute the "valid" code for any ID
    // that does not exist.
    //
    // One shared message, too: saying "revoked" out loud confirms the ID is
    // real, which is the enumeration oracle architecture.md §6 rules out.
    //
    // Still imperfect -- this returns faster than a real verification does,
    // which leaks which IDs exist by timing instead. Closing that needs the
    // dummy-key path from §6: a real random key held by the verifier, HMAC'd
    // against so the work matches. That lands with the daemon in Phase 2.
    if (found != Lookup::Found || device.status != 1) {
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
