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

Connection* ConnectionTracker::getConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        return &it->second;
    }
    
    // Try reverse tuple (for bidirectional matching)
    auto rev = connections_.find(tuple.reverse());
    if (rev != connections_.end()) {
        return &rev->second;
    }
    
    return nullptr;
}

void ConnectionTracker::updateConnection(Connection* conn, size_t packet_size, bool is_outbound) {
    if (!conn) return;
    
    conn->last_seen = std::chrono::steady_clock::now();
    
    if (is_outbound) {
        conn->packets_out++;
        conn->bytes_out += packet_size;
    } else {
        conn->packets_in++;
        conn->bytes_in += packet_size;
    }
}

void ConnectionTracker::classifyConnection(Connection* conn, AppType app, const std::string& sni) {
    if (!conn) return;
    
    if (conn->state != ConnectionState::CLASSIFIED) {
        conn->app_type = app;
        conn->sni = sni;
        conn->state = ConnectionState::CLASSIFIED;
        classified_count_++;
    }
}

void ConnectionTracker::blockConnection(Connection* conn) {
    if (!conn) return;
    
    conn->state = ConnectionState::BLOCKED;
    conn->action = PacketAction::DROP;
    blocked_count_++;
}

void ConnectionTracker::closeConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        it->second.state = ConnectionState::CLOSED;
    }
}

size_t ConnectionTracker::cleanupStale(std::chrono::seconds timeout) {
    auto now = std::chrono::steady_clock::now();
    size_t removed = 0;
    
    for (auto it = connections_.begin(); it != connections_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_seen);
        
        if (age > timeout || it->second.state == ConnectionState::CLOSED) {
            it = connections_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    return removed;
}
