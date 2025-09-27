#include "crypto/secure_random.h"

#if defined(_WIN32)
  #define NOMINMAX
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#else
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #if defined(__linux__)
    #include <sys/syscall.h>
    #include <linux/random.h>
  #endif
#endif

#include <cstring>

namespace miq {

#if !defined(_WIN32)
static bool urandom_read(uint8_t* out, size_t len){
    int fd = ::open("/dev/urandom", O_RDONLY);
    if(fd < 0) return false;
    size_t off=0;
    while(off < len){
        ssize_t r = ::read(fd, out+off, len-off);
        if(r <= 0){ if(errno == EINTR) continue; ::close(fd); return false; }
        off += (size_t)r;
    }
    ::close(fd);
    return true;
}
#endif

bool secure_random(uint8_t* out, size_t len, std::string* err){
#if defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(st != 0){
        if(err) *err = "BCryptGenRandom failed";
        return false;
    }
    return true;
#elif defined(__linux__)
    // Try getrandom() first
    ssize_t r = syscall(SYS_getrandom, out, len, 0);
    if(r == (ssize_t)len) return true;
    // Fallback to /dev/urandom
    if(urandom_read(out, len)) return true;
    if(err) *err = "getrandom()/urandom failed";
    return false;
#else
    if(urandom_read(out, len)) return true;
    if(err) *err = "/dev/urandom failed";
    return false;
#endif
}

}
