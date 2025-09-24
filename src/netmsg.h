
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "constants.h"
namespace miq {
struct NetMsg { char cmd[12]; std::vector<uint8_t> payload; };
std::vector<uint8_t> encode_msg(const std::string& cmd, const std::vector<uint8_t>& payload);
bool decode_msg(const std::vector<uint8_t>& in, size_t& offset, NetMsg& out);
}
