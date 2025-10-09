#pragma once
#include <string>

namespace miq {

// Returns a writable wallet data dir (used for nodes.txt).
// Windows: %APPDATA%\\MiqWallet
// macOS:   $HOME/Library/Application Support/MiqWallet
// Linux:   $HOME/.miqwallet
std::string wallet_data_dir();

// Ensure directory exists (mkdir -p style for one level).
bool ensure_dir(const std::string& path);

}
