// DEV ONLY. Prints the current code for a device by reading its key straight
// from the keystore -- exactly what nobody should be able to do in production.
// It exists so the gate can be tested before a keychain is built.
//
// Not part of `make all`. Build it with `make devcode`, never on the server,
// and never ship it in a container.
//
//   usage: devcode ID

#include "../../core/otp.hpp"
#include "../../core/keystore.hpp"

#include <openssl/crypto.h>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: devcode ID   (DEV ONLY -- reads the key from the keystore)" << std::endl;
        return 2;
    }
    Device d;
    if (find_device(argv[1], d) != Lookup::Found) {
        std::cerr << "no device " << argv[1] << std::endl;
        return 1;
    }
    std::string code = pad_and_convert(totp(d.key, time(nullptr)));
    OPENSSL_cleanse(&d.key[0], d.key.size());
    std::cerr << "devcode: DEV ONLY" << (d.status == 1 ? "" : " -- device is REVOKED") << std::endl;
    std::cout << code << std::endl;
    return 0;
}
