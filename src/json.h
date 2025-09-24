
#pragma once
#include <string>
#include <variant>
#include <vector>
#include <map>
namespace miq {
struct JNull{};
using JVal = std::variant<JNull, bool, double, std::string, std::vector<class JNode>, std::map<std::string, class JNode>>;
class JNode { public: JVal v; };
bool json_parse(const std::string& s, JNode& out);
std::string json_dump(const JNode& n);
}
