#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace DPI {

// ============================================================================
// Fast Path Processor Thread
// ============================================================================
//
// Each FP thread is responsible for:
// 1. Receiving packets from its input queue (fed by LB)
// 2. Connection tracking (maintaining flow state)
// 3. Deep Packet Inspection (SNI extraction, protocol detection)
// 4. Rule matching (blocking decisions)
// 5. Forwarding or dropping packets
//
// FP threads are the workhorses of the DPI engine. They do the heavy lifting
// of actually inspecting packet contents and making decisions.
//
// ============================================================================

// Callback type for packet output (forwarding)
using PacketOutputCallback = std::function<void(const PacketJob&, PacketAction)>;
class FastPathProcessor {
public:
    // Constructor
    // fp_id: ID of this FP (0, 1, 2, ...)
    // rule_manager: Shared rule manager (read-only from FP perspective)
    // output_callback: Called when packet should be forwarded
    FastPathProcessor(int fp_id,
                      RuleManager* rule_manager,
                      PacketOutputCallback output_callback);
    
    ~FastPathProcessor();
    
    // Start the FP thread
    void start();
    
    // Stop the FP thread
    void stop();
    
    // Get input queue (for LB to push packets)
    ThreadSafeQueue<PacketJob>& getInputQueue() { return input_queue_; }
    
    // Get connection tracker (for reporting)
    ConnectionTracker& getConnectionTracker() { return conn_tracker_; }
    
    // Get statistics
    struct FPStats {
        uint64_t packets_processed;
        uint64_t packets_forwarded;
        uint64_t packets_dropped;
        uint64_t connections_tracked;
        uint64_t sni_extractions;
        uint64_t classification_hits;
    };
    
    FPStats getStats() const;
    
    // Get FP ID
    int getId() const { return fp_id_; }
    
    // Check if running
    bool isRunning() const { return running_; }
