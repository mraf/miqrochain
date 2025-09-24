
#pragma once
#include <string>
#include <vector>
namespace miq {
std::string base58_encode(const std::vector<uint8_t>& in);
bool base58_decode(const std::string& s, std::vector<uint8_t>& out);
}
