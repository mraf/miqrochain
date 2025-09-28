#pragma once
#include <string>

namespace miq {

// Returns e.g. "C:\\Users\\You\\AppData\\Roaming\\miqro\\wallets\\default\\wallet.kv"
std::string default_wallet_file();

// Reads "address=<base58>" from default wallet file. Returns true & sets out on success.
// If built with MIQ_ENABLE_WALLET_ENC=ON and the file is encrypted, it will be
// transparently decrypted using the environment variable MIQ_WALLET_PASSPHRASE.
bool load_default_wallet_address(std::string& out);

// Writes priv/pub/address to the default wallet file. If MIQ_ENABLE_WALLET_ENC=ON
// and the environment variable MIQ_WALLET_PASSPHRASE is non-empty, the file is
// written encrypted (AES-256-GCM). Otherwise, legacy plaintext is used.
bool save_default_wallet(const std::string& priv_hex,
                         const std::string& pub_hex,
                         const std::string& address);

}
