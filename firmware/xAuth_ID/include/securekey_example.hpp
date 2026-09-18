#pragma once

// Do not write this file by hand. Generate the real one, together with the
// keystore entry, so the ID and the key can never belong to different devices:
//
//     build/provision add --label "primary" --firmware-header firmware/xAuth_ID/include/securekey.hpp
//
// securekey.hpp is gitignored. This example only shows the shape.

#define DEVICE_ID  "ABCD"
#define SECURE_KEY "0000000000000000000000000000000000000000000000000000000000000000"
