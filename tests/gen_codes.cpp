// Test helper: prints the code core/otp.cpp produces for each counter given on
// argv. Deliberately dumb -- comparison against the golden vectors happens in
// check_vectors.py, so this stays free of any parsing that could itself be wrong.
//
//   usage: otpgen <key> <counter> [counter...]
#include "../core/otp.hpp"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: otpgen <key> <counter> [counter...]" << std::endl;
        return 2;
    }
    std::string key = argv[1];
    for (int i = 2; i < argc; i++) {
        uint64_t counter = std::stoull(argv[i]);
        std::cout << pad_and_convert(totp_for_counter(key, counter)) << std::endl;
    }
    return 0;
}
