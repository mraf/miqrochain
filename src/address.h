#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {
bool decode_p2pkh_address(const std::string& addr, std::vector<uint8_t>& out_pkh);
std::string encode_p2pkh_address(const std::vector<uint8_t>& pkh);
}
