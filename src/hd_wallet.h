#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// Provisional SLIP-44 coin type for MIQ (update when registered)
static constexpr uint32_t MIQ_COIN_TYPE = 5355; // placeholder

struct HdAccountMeta {
    uint32_t account = 0;
    uint32_t next_recv = 0;   // external chain (0)
    uint32_t next_change = 0; // change chain   (1)
};

// BIP-39 + BIP-32 light HD wallet. Stores only the seed (encrypted) + simple INI metadata.
class HdWallet {
public:
    HdWallet(const std::vector<uint8_t>& seed, const HdAccountMeta& meta);

    // 12/24-word English mnemonic
    static bool GenerateMnemonic(int entropy_bits, std::string& out_mnemonic);

    // BIP-39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512)
    static bool MnemonicToSeed(const std::string& mnemonic,
                               const std::string& passphrase,
                               std::vector<uint8_t>& out_seed);

    // Derive key for m/44'/MIQ'/account'/chain/index. Returns 32B priv + 33B compressed pub.
    bool DerivePrivPub(uint32_t account, uint32_t chain, uint32_t index,
                       std::vector<uint8_t>& out_priv,
                       std::vector<uint8_t>& out_pub) const;

    // Next external address (increments next_recv).
    bool GetNewAddress(std::string& out_addr);

    // Read-only: external address at index (does not change counters).
    bool GetAddressAt(uint32_t index, std::string& out_addr) const;

    const HdAccountMeta& meta() const { return meta_; }
    void set_meta(const HdAccountMeta& m) { meta_ = m; }

    static std::string MetaToIni(const HdAccountMeta& m);
    static bool MetaFromIni(const std::string& text, HdAccountMeta& m_out);

private:
    std::vector<uint8_t> seed_; // 64 bytes
    HdAccountMeta meta_;
};

// Save/Load encrypted seed + INI metadata under a wallet directory.
// If MIQ_ENABLE_WALLET_ENC and walletpass != "", the seed is encrypted.
bool SaveHdWallet(const std::string& path_dir,
                  const std::vector<uint8_t>& seed,
                  const HdAccountMeta& meta,
                  const std::string& walletpass,
                  std::string& err);

bool LoadHdWallet(const std::string& path_dir,
                  std::vector<uint8_t>& out_seed,
                  HdAccountMeta& out_meta,
                  const std::string& walletpass,
                  std::string& err);

// Convert a compressed pubkey (33B) to Base58 P2PKH using your chain’s version byte.
std::string PubkeyToAddress(const std::vector<uint8_t>& pub33);

}
