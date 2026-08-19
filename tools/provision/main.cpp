#include "../../core/keystore.hpp"

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>

// Provisions a new device: generates a public ID and a secret, writes both to
// the keystore, prints the ID. The secret is never printed -- it goes to the
// database and onto the physical device, and nowhere else.

std::string generate_device_id(int length = 4) {
    static const char alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // 32 chars
    std::vector<unsigned char> buf(length);

    if (RAND_bytes(buf.data(), length) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    std::string id;
    for (unsigned char b : buf) {
        // 256 is an exact multiple of 32, so this modulo introduces no bias.
        id += alphabet[b % 32];
    }
    return id;
}

std::string generate_key(int bytes = 64) {
    // Was popen("openssl rand -hex 64"), which depended on an openssl binary
    // being on PATH and never checked whether the pipe opened. RAND_bytes is the
    // same CSPRNG, already linked in, and can actually report failure.
    std::vector<unsigned char> buf(bytes);
    if (RAND_bytes(buf.data(), bytes) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    // Hex, lowercase -- the ASCII hex characters are what gets fed to HMAC, on
    // both the server and the firmware. Keep this format; changing it silently
    // invalidates every device already in the field.
    static const char hex[] = "0123456789abcdef";
    std::string key;
    key.reserve(bytes * 2);
    for (unsigned char b : buf) {
        key += hex[b >> 4];
        key += hex[b & 0x0F];
    }

    OPENSSL_cleanse(buf.data(), buf.size());
    return key;
}

Device generate_user(){
    Device user;
    user.id = generate_device_id();
    user.key = generate_key();
    return user;
}

int main(){

    Device new_user = generate_user();

    if (!add_device(new_user)) {
        std::cerr<<"Provisioning failed -- device not written."<<std::endl;
        OPENSSL_cleanse(&new_user.key[0], new_user.key.size());
        return 1;
    }

    std::cout<<"Generated user: "<<new_user.id<<std::endl;

    OPENSSL_cleanse(&new_user.key[0], new_user.key.size());
    return 0;
}
