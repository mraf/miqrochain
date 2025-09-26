#pragma once
#include <string>

namespace miq {

// Try to handle a JSON-RPC request if it's "getminerstats".
// - body: raw HTTP JSON body
// - handled: set to true if this function produced a reply
// Returns JSON string result if handled==true, otherwise empty string.
std::string rpc_maybe_handle_minerstats(const std::string& body, bool& handled);

} // namespace miq
