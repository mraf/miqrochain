#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {
std::vector<uint8_t> from_hex(const std::string& hex);
std::string to_hex(const std::vector<uint8_t>& v);
}
