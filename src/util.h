#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace miq {

// UNIX time (seconds since epoch)
uint64_t now();

// Convenience hex helpers (back-compat for callers that use util.h)
std::string hex(const std::vector<uint8_t>& v);
std::vector<uint8_t> hex_to_bytes(const std::string& h);

} // namespace miq

