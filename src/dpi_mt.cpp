// Multi-threaded DPI Engine - Fixed Version
// Architecture: Reader -> LB threads -> FP threads -> Output

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
};

// =============================================================================
// Statistics (thread-safe)
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    
    // Per-app stats (protected by mutex)
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;
    
    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }
};

// =============================================================================
// Fast Path Processor (one per FP thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, TSQueue<Packet>* output_queue)
        : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t processed() const { return processed_; }

private:
    int id_;
    Rules* rules_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            
            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.packets++;
            flow.bytes += pkt.data.size();
            
            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }
            
            // Check blocking
            if (!flow.blocked) {
                flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
            }
            
            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            
            // Forward or drop
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        // Try SNI extraction for HTTPS
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }
        
        // Try HTTP Host extraction
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }
        
        // DNS
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            flow.app_type = AppType::DNS;
            flow.classified = true;
            return;
        }
        
        // Port-based fallback (but don't mark as classified - might get SNI later)
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            // Hash to select FP
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// DPI Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
    };
    
    DPIEngine(const Config& cfg) : config_(cfg) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              DPI ENGINE v2.0 (Multi-threaded)                 ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg.num_lbs 
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        // Create FP threads
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &stats_, &output_queue_));
        }
        
        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
