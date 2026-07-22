#include "fast_path.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// FastPathProcessor Implementation
// ============================================================================

FastPathProcessor::FastPathProcessor(int fp_id,
                                     RuleManager* rule_manager,
                                     PacketOutputCallback output_callback)
    : fp_id_(fp_id),
      input_queue_(10000),
      conn_tracker_(fp_id),
      rule_manager_(rule_manager),
      output_callback_(std::move(output_callback)) {
}

FastPathProcessor::~FastPathProcessor() {
    stop();
}

void FastPathProcessor::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&FastPathProcessor::run, this);
    
    std::cout << "[FP" << fp_id_ << "] Started\n";
}

void FastPathProcessor::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[FP" << fp_id_ << "] Stopped (processed " 
              << packets_processed_ << " packets)\n";
}

void FastPathProcessor::run() {
    while (running_) {
        // Get packet from input queue
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            // Periodically cleanup stale connections
            conn_tracker_.cleanupStale(std::chrono::seconds(300));
            continue;
        }
        
        packets_processed_++;
        
        // Process the packet
        PacketAction action = processPacket(*job_opt);
        
        // Call output callback
        if (output_callback_) {
            output_callback_(*job_opt, action);
        }
        
        // Update stats
        if (action == PacketAction::DROP) {
            packets_dropped_++;
        } else {
            packets_forwarded_++;
        }
    }
}

PacketAction FastPathProcessor::processPacket(PacketJob& job) {
    // Get or create connection
    Connection* conn = conn_tracker_.getOrCreateConnection(job.tuple);
    if (!conn) {
        // Should not happen, but handle gracefully
        return PacketAction::FORWARD;
    }
    
    // Update connection stats
    bool is_outbound = true;  // In this model, all packets from user are outbound
    conn_tracker_.updateConnection(conn, job.data.size(), is_outbound);
    
    // Update TCP state if applicable
    if (job.tuple.protocol == 6) {  // TCP
        updateTCPState(conn, job.tcp_flags);
    }
    
    // If connection is already blocked, drop immediately
    if (conn->state == ConnectionState::BLOCKED) {
        return PacketAction::DROP;
    }
   
