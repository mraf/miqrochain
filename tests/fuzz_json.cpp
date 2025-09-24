
#include "json.h"
#include <cstdlib>
#include <string>
int main(int argc, char** argv){
    if(argc<2) return 0;
    std::string s(argv[1]);
    miq::JNode n; miq::json_parse(s, n);
    return 0;
}
