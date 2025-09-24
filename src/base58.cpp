#include "base58.h"
#include <cstring>  // for std::strchr

static const char* ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int idx(char c) {
    const char* p = std::strchr(ALPH, c);
    return p ? int(p - ALPH) : -1;
}

std::string miq::base58_encode(const std::vector<uint8_t>& in) {
    std::vector<unsigned char> b(in.begin(), in.end());

    int zeros = 0;
    while (zeros < (int)b.size() && b[zeros] == 0) zeros++;

    std::vector<unsigned char> tmp(b.size() * 138 / 100 + 1);
    int j = 0;

    for (size_t i = (size_t)zeros; i < b.size(); ++i) {
        int carry = b[i];
        int k = (int)tmp.size() - 1;  // explicit cast to avoid C4267

        // for (; carry || k >= j; --k) { ... }
        // Use explicit bounds; never write when k < 0
        for (; carry || k >= j; --k) {
            int val = (k >= 0) ? tmp[(size_t)k] : 0;
            int x = val * 256 + carry;
            if (k >= 0) tmp[(size_t)k] = (unsigned char)(x % 58);
            carry = x / 58;
        }
        j = k + 1;
    }

    std::string out;
    out.assign(zeros, '1');

    for (size_t i = 0; i < tmp.size(); ++i) {
        if (tmp[i]) {
            for (size_t k = i; k < tmp.size(); ++k) out.push_back(ALPH[tmp[k]]);
            break;
        }
    }
    return out;
}

bool miq::base58_decode(const std::string& s, std::vector<uint8_t>& out) {
    int zeros = 0;
    while (zeros < (int)s.size() && s[zeros] == '1') zeros++;

    std::vector<int> b;
    b.reserve(s.size());
    for (char c : s) {
        int v = idx(c);
        if (v < 0) return false;
        b.push_back(v);
    }

    std::vector<unsigned char> tmp(s.size() * 733 / 1000 + 1);
    int j = 0;

    for (size_t i = (size_t)zeros; i < b.size(); ++i) {
        int carry = b[i];
        int k = (int)tmp.size() - 1;  // explicit cast to avoid C4267
        for (; carry || k >= j; --k) {
            int val = (k >= 0) ? tmp[(size_t)k] : 0;
            int x = val * 58 + carry;
            if (k >= 0) tmp[(size_t)k] = (unsigned char)(x % 256);
            carry = x / 256;
        }
        j = k + 1;
    }

    out.assign(zeros, 0);
    for (size_t i = 0; i < tmp.size(); ++i) {
        if (tmp[i]) {
            out.insert(out.end(), tmp.begin() + i, tmp.end());
            break;
        }
    }
    return true;
}

