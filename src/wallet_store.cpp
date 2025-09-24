#include "wallet_store.h"
#include <filesystem>
#include <fstream>
#include <cstdlib>

namespace fs = std::filesystem;
namespace miq {

static std::string appdata_dir() {
    const char* a = std::getenv("APPDATA");
    if (!a || !*a) return std::string(".");
    fs::path p(a);
    p /= "miqro";
    fs::create_directories(p);
    return p.string();
}

std::string default_wallet_file() {
    fs::path p(appdata_dir());
    p /= "wallets";
    p /= "default";
    fs::create_directories(p);
    p /= "wallet.kv";
    return p.string();
}

bool load_default_wallet_address(std::string& out) {
    std::ifstream f(default_wallet_file(), std::ios::binary);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("address=", 0) == 0) { out = line.substr(8); return !out.empty(); }
    }
    return false;
}

bool save_default_wallet(const std::string& priv_hex,
                         const std::string& pub_hex,
                         const std::string& address) {
    const auto path = default_wallet_file();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << "version=1\n";
    f << "curve=secp256k1\n";
    f << "address=" << address << "\n";
    f << "priv_hex=" << priv_hex << "\n";
    f << "pub_hex="  << pub_hex  << "\n";
    f.flush();
    // Also write address.txt for convenience
    std::ofstream a(fs::path(path).parent_path() / "address.txt", std::ios::binary | std::ios::trunc);
    if (a) { a << address << "\n"; a.flush(); }
    return true;
}

} // namespace miq
