#pragma once
//
// wallet_encryptor.h — optional wallet at-rest encryption (PBKDF2 + AES-256-GCM)
// Default OFF: enable with -DMIQ_ENABLE_WALLET_ENC=ON in CMake (snippet below).
//
#include <cstdint>
#include <string>
#include <vector>

namespace miq {

// Encrypt plaintext and write an authenticated ciphertext file at `path`.
// Atomic write via <path>.tmp -> rename. Returns true on success.
bool wallet_encrypt_to_file(const std::string& path,
                            const std::vector<uint8_t>& plaintext,
                            const std::string& passphrase,
                            std::string& err);

// Read & decrypt wallet file from `path` into plaintext_out.
// Returns false if file corrupt, wrong password, or feature disabled.
bool wallet_decrypt_from_file(const std::string& path,
                              std::vector<uint8_t>& plaintext_out,
                              const std::string& passphrase,
                              std::string& err);

}
