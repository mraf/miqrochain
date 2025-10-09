#include "paths.h"
#include <cstdlib>
#include <string>

#ifdef _WIN32
  #include <windows.h>
  #include <shlobj.h>
  #include <direct.h>
  #define miq_mkdir(p) _mkdir(p)
#else
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <unistd.h>
  #define miq_mkdir(p) mkdir(p, 0755)
#endif

namespace miq {

bool ensure_dir(const std::string& p){
#ifdef _WIN32
    if(_mkdir(p.c_str())==0) return true;
    DWORD attr = GetFileAttributesA(p.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    if(mkdir(p.c_str(),0755)==0) return true;
    struct stat st; if(stat(p.c_str(), &st)==0 && S_ISDIR(st.st_mode)) return true;
    return false;
#endif
}

static std::string joinp(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}

std::string wallet_data_dir(){
#ifdef _WIN32
    char path[MAX_PATH] = {0};
    if(SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))){
        std::string d = joinp(path, "MiqWallet");
        ensure_dir(d);
        return d;
    }
    std::string d = "MiqWallet";
    ensure_dir(d);
    return d;
#elif __APPLE__
    const char* home = std::getenv("HOME");
    std::string base = (home && *home) ? std::string(home) : std::string(".");
    std::string d = joinp(joinp(base, "Library/Application Support"), "MiqWallet");
    ensure_dir(joinp(base, "Library"));
    ensure_dir(joinp(base, "Library/Application Support"));
    ensure_dir(d);
    return d;
#else
    const char* home = std::getenv("HOME");
    std::string base = (home && *home) ? std::string(home) : std::string(".");
    std::string d = joinp(base, ".miqwallet");
    ensure_dir(d);
    return d;
#endif
}

}
