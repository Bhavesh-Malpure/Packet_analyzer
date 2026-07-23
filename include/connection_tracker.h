#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <chrono>
#include <functional>

namespace DPI {

// ============================================================================
// Connection Tracker - Maintains flow table for all active connections
// ============================================================================
//
// Each FP thread has its own ConnectionTracker instance (no sharing needed
// since connections are consistently hashed to the same FP).
//
// Features:
// - Track connection state (NEW -> ESTABLISHED -> CLASSIFIED -> CLOSED)
// - Store classification results (app type, SNI)
// - Maintain per-flow statistics
// - Timeout inactive connections
// ============================================================================
