#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace miq {
std::string base58check_encode(uint8_t version, const std::vector<uint8_t>& payload);
bool base58check_decode(const std::string& s, uint8_t& version, std::vector<uint8_t>& payload);
}
