#pragma once
#include <string>
namespace miq {
// Returns e.g. "C:\\Users\\You\\AppData\\Roaming\\miqro\\wallets\\default\\wallet.kv"
std::string default_wallet_file();
// Reads "address=<base58>" from default wallet file. Returns true & sets out on success.
bool load_default_wallet_address(std::string& out);
// Writes priv/pub/address hex/base58 to default wallet file for persistence.
bool save_default_wallet(const std::string& priv_hex,
                         const std::string& pub_hex,
                         const std::string& address);
}
