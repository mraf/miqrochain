#include "nat.h"

// Try to use project logging if available; otherwise fall back to stderr.
#include "log.h"
#include <cstdio>

#ifndef LOG_INFO
  #define LOG_INFO(...) do { std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n"); } while(0)
#endif
#ifndef LOG_WARN
  #define LOG_WARN(...) do { std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n"); } while(0)
#endif

#if defined(MIQ_ENABLE_UPNP)
  #include <miniupnpc/miniupnpc.h>
  #include <miniupnpc/upnpcommands.h>
  #include <cstring>
  #include <cstdio>
#endif

namespace miq {

bool TryOpenP2PPort(uint16_t port, std::string* external_ip_out){
#if defined(MIQ_ENABLE_UPNP)
    UPNPDev* devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, nullptr);
    if(!devlist){ LOG_INFO("UPnP: no IGD devices found"); return false; }

    UPNPUrls urls; IGDdatas data;
    char lanaddr[64] = {0};
    int r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if(r != 1){ LOG_WARN("UPnP: no valid IGD (code=%d)", r); freeUPNPDevlist(devlist); return false; }

    char extip[40] = {0};
    if(UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, extip) == UPNPCOMMAND_SUCCESS){
        if(external_ip_out) *external_ip_out = std::string(extip);
        LOG_INFO("UPnP: external IP: %s", extip);
    }

    char port_str[16]; std::snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    int add = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                  port_str, port_str, lanaddr, "miqrochain p2p",
                                  "TCP", nullptr, "0");
    if(add == UPNPCOMMAND_SUCCESS){
        LOG_INFO("UPnP: mapped TCP %s -> %s:%s", port_str, lanaddr, port_str);
        freeUPNPUrls(&urls); freeUPNPDevlist(devlist);
        return true;
    }else{
        LOG_WARN("UPnP: mapping failed (code=%d)", add);
        freeUPNPUrls(&urls); freeUPNPDevlist(devlist);
        return false;
    }
#else
    (void)port; (void)external_ip_out;
    LOG_INFO("UPnP/NAT-PMP disabled at build time (MIQ_ENABLE_UPNP=0).");
    return false;
#endif
}

}
