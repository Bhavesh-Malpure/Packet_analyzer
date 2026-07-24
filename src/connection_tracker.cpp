#include "connection_tracker.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <mutex>

namespace DPI {

// ============================================================================
// ConnectionTracker Implementation
// ============================================================================

ConnectionTracker::ConnectionTracker(int fp_id, size_t max_connections)
    : fp_id_(fp_id), max_connections_(max_connections) {
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    
    if (it != connections_.end()) {
        return &it->second;
    }
    
    // Check if we need to evict old connections
    if (connections_.size() >= max_connections_) {
        evictOldest();
    }
    
    // Create new connection
    Connection conn;
    conn.tuple = tuple;
    conn.state = ConnectionState::NEW;
    conn.first_seen = std::chrono::steady_clock::now();
    conn.last_seen = conn.first_seen;
    
    auto result = connections_.emplace(tuple, std::move(conn));
    total_seen_++;
    
    return &result.first->second;
}
