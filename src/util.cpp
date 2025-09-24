#include "util.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>   // <-- fix: needed for std::chrono

namespace miq {

uint64_t now() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count()
    );
}

std::string hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : v) o << std::setw(2) << (int)b;
    return o.str();
}

static uint8_t hv(char c){
    if(c>='0'&&c<='9') return uint8_t(c-'0');
    if(c>='a'&&c<='f') return uint8_t(c-'a'+10);
    if(c>='A'&&c<='F') return uint8_t(c-'A'+10);
    throw std::runtime_error("hex");
}

std::vector<uint8_t> hex_to_bytes(const std::string& h){
    if(h.size()%2) throw std::runtime_error("hexlen");
    std::vector<uint8_t> o; o.reserve(h.size()/2);
    for(size_t i=0;i<h.size();i+=2) o.push_back(uint8_t((hv(h[i])<<4)|hv(h[i+1])));
    return o;
}

} // namespace miq
