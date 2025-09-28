#pragma once
#include <cstdint>
#include <string>

namespace miq {
// Attempts NAT traversal / port mapping for P2P port. Returns true on success.
// No-op unless compiled with MIQ_ENABLE_UPNP=1 and miniupnpc linked.
bool TryOpenP2PPort(uint16_t port, std::string* external_ip_out = nullptr);
}
