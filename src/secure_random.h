#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

namespace miq {

bool secure_random(uint8_t* out, size_t len, std::string* err = nullptr);

// Convenience helpers
inline std::vector<uint8_t> random_bytes(size_t n, std::string* err=nullptr){
    std::vector<uint8_t> v(n);
    if(!secure_random(v.data(), v.size(), err)) v.clear();
    return v;
}

}
