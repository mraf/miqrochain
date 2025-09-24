
#include "json.h"
#include <cctype>
#include <sstream>
namespace miq {
static void skip(const std::string& s, size_t& i){ while(i<s.size() && isspace((unsigned char)s[i])) ++i; }
static bool parse_string(const std::string& s, size_t& i, std::string& out){
    if(s[i]!='"') return false; ++i; std::ostringstream o; while(i<s.size() && s[i]!='"'){ if(s[i]=='\\'){ ++i; if(i>=s.size()) return false; char c=s[i]; if(c=='"'||c=='\\'||c=='/') o<<c; else if(c=='b') o<<'\b'; else if(c=='f') o<<'\f'; else if(c=='n') o<<'\n'; else if(c=='r') o<<'\r'; else if(c=='t') o<<'\t'; else return false; } else o<<s[i]; ++i; } if(i>=s.size()||s[i]!='"') return false; ++i; out=o.str(); return true;
}
static bool parse_value(const std::string& s, size_t& i, JNode& out);
static bool parse_array(const std::string& s, size_t& i, JNode& out){
    if(s[i]!='[') return false; ++i; skip(s,i); std::vector<JNode> arr; if(s[i]==']'){ ++i; out.v=arr; return true; }
    while(true){ JNode val; if(!parse_value(s,i,val)) return false; arr.push_back(val); skip(s,i); if(s[i]==','){ ++i; skip(s,i); continue; } if(s[i]==']'){ ++i; out.v=arr; return true; } return false; }
}
static bool parse_object(const std::string& s, size_t& i, JNode& out){
    if(s[i]!='{') return false; ++i; skip(s,i); std::map<std::string,JNode> obj; if(s[i]=='}'){ ++i; out.v=obj; return true; }
    while(true){ std::string k; if(!parse_string(s,i,k)) return false; skip(s,i); if(s[i]!=':') return false; ++i; skip(s,i); JNode val; if(!parse_value(s,i,val)) return false; obj[k]=val; skip(s,i); if(s[i]==','){ ++i; skip(s,i); continue; } if(s[i]=='}'){ ++i; out.v=obj; return true; } return false; }
}
static bool parse_number(const std::string& s, size_t& i, double& out){
    size_t j=i; if(s[i]=='-') ++i; while(i<s.size() && isdigit((unsigned char)s[i])) ++i; if(i<s.size() && s[i]=='.'){ ++i; while(i<s.size()&&isdigit((unsigned char)s[i])) ++i; } out = std::stod(s.substr(j, i-j)); return true;
}
static bool parse_value(const std::string& s, size_t& i, JNode& out){
    skip(s,i); if(i>=s.size()) return false;
    if(s[i]=='"'){ std::string str; if(!parse_string(s,i,str)) return false; out.v=str; return true; }
    if(s[i]=='{') return parse_object(s,i,out);
    if(s[i]=='[') return parse_array(s,i,out);
    if(s.compare(i,4,"true")==0){ i+=4; out.v=true; return true; }
    if(s.compare(i,5,"false")==0){ i+=5; out.v=false; return true; }
    if(s.compare(i,4,"null")==0){ i+=4; out.v=JNull{}; return true; }
    double num; if(parse_number(s,i,num)){ out.v=num; return true; }
    return false;
}
bool json_parse(const std::string& s, JNode& out){ size_t i=0; bool ok=parse_value(s,i,out); if(!ok) return false; skip(s,i); return i==s.size(); }
static void dump(const JNode& n, std::ostringstream& o){
    if(std::holds_alternative<JNull>(n.v)) o<<"null";
    else if(std::holds_alternative<bool>(n.v)) o<<(std::get<bool>(n.v)?"true":"false");
    else if(std::holds_alternative<double>(n.v)) o<<std::get<double>(n.v);
    else if(std::holds_alternative<std::string>(n.v)) o<<'"'<<std::get<std::string>(n.v)<<'"';
    else if(std::holds_alternative<std::vector<JNode>>(n.v)){ o<<'['; const auto& a=std::get<std::vector<JNode>>(n.v); for(size_t i=0;i<a.size();++i){ if(i) o<<','; dump(a[i],o);} o<<']'; }
    else { o<<'{'; const auto& m=std::get<std::map<std::string,JNode>>(n.v); size_t i=0; for(auto& kv: m){ if(i++) o<<','; o<<'"'<<kv.first<<'"'<<':' ; dump(kv.second,o);} o<<'}'; }
}
std::string json_dump(const JNode& n){ std::ostringstream o; dump(n,o); return o.str(); }
}
