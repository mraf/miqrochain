#include "mtp.h"
#include <algorithm>
#include <ctime>

namespace miq {

int64_t compute_mtp(const std::shared_ptr<HeaderRec>& parent){
    if (!parent) return 0;
    // Collect up to last 11 header times walking parents: parent, grandparent, ...
    std::vector<int64_t> times;
    times.reserve(MIQ_MTP_WINDOW);
    auto cur = parent;
    for (int i = 0; i < MIQ_MTP_WINDOW && cur; ++i) {
        times.push_back(cur->time);
        cur = cur->parent;
    }
    if (times.empty()) return 0;
    std::sort(times.begin(), times.end());
    // median element (floor for odd length)
    return times[times.size() / 2];
}

static inline int64_t now_utc(){
    return static_cast<int64_t>(std::time(nullptr));
}

bool check_header_time_rules(const BlockHeader& h,
                             const std::shared_ptr<HeaderRec>& parent,
                             std::string& err)
{
    const int64_t mtp = compute_mtp(parent);
    if (!(h.time > mtp)) {
        err = "bad-header-time: not greater than MTP(parent)";
        return false;
    }
    const int64_t max_future = now_utc() + MIQ_MAX_FUTURE_DRIFT_SECS;
    if (h.time > max_future) {
        err = "bad-header-time: too far in future";
        return false;
    }
    return true;
}

bool check_block_time_rules(const Block& b,
                            const std::shared_ptr<HeaderRec>& parent,
                            std::string& err)
{
    // Same rules applied at block stage
    const int64_t mtp = compute_mtp(parent);
    if (!(b.header.time > mtp)) {
        err = "bad-block-time: not greater than MTP(parent)";
        return false;
    }
    const int64_t max_future = now_utc() + MIQ_MAX_FUTURE_DRIFT_SECS;
    if (b.header.time > max_future) {
        err = "bad-block-time: too far in future";
        return false;
    }
    return true;
}

}
