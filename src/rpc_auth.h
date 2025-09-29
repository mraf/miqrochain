#pragma once
#include <string>
#include <vector>

namespace miq {

// Loads the expected RPC token, preferring:
//   1) env MIQ_RPC_TOKEN,
//   2) <datadir>/.cookie     (created by rpc_enable_auth_cookie),
//   3) empty (no token)      (should never happen in prod; we reject if empty)
bool rpc_load_expected_token(const std::string& datadir, std::string& out_token, std::string* err=nullptr);

// Parse "Authorization: Bearer <token>" style header.
bool rpc_parse_bearer(const std::string& header_value, std::string& out_token);

// Constant-time compare
bool rpc_timing_safe_eq(const std::string& a, const std::string& b);

}
