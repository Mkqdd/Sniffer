#include "ConnectionTracker.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <ctime>
#include <iostream>

ConnectionTracker::ConnectionTracker() : connection_counter_(0), udp_flow_timeout_(30.0), timeout_sequence_counter_(0) {
    // Initialize random number generator
    srand(time(nullptr));
}

ConnectionTracker::~ConnectionTracker() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    connections_.clear();
    
    std::lock_guard<std::mutex> completed_lock(completed_connections_mutex_);
    completed_connections_.clear();
    
    std::lock_guard<std::mutex> timeout_lock(udp_timeout_mutex_);
    udp_timeout_tree_.clear();
    udp_connection_to_timeout_.clear();
}

void ConnectionTracker::processPacket(const PacketMetadata& metadata) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    // Generate connection key
    std::string conn_key = generateConnectionKey(metadata.srcIP, metadata.srcPort, 
                                               metadata.dstIP, metadata.dstPort, 
                                               metadata.protocol);
    
    // Find or create connection
    auto it = connections_.find(conn_key);
    if (it == connections_.end()) {
        // Create new connection
        ConnectionStats new_conn;
        new_conn.uid = generateConnectionUID(metadata.srcIP, metadata.srcPort, 
                                           metadata.dstIP, metadata.dstPort, 
                                           metadata.protocol);
        new_conn.upstream_h = metadata.srcIP;
        new_conn.upstream_p = metadata.srcPort;
        new_conn.downstream_h = metadata.dstIP;
        new_conn.downstream_p = metadata.dstPort;
        new_conn.proto = metadata.protocol;
        new_conn.service = detectService(metadata.protocol, metadata.dstPort);
        new_conn.start_time = metadata.timestamp;
        new_conn.last_seen = metadata.timestamp;
        new_conn.ip_proto = (metadata.protocol == "TCP") ? 6 : 
                           (metadata.protocol == "UDP") ? 17 : 
                           (metadata.protocol == "ICMP") ? 1 : 0;
        
        connections_[conn_key] = new_conn;
        it = connections_.find(conn_key);
    }
    
    ConnectionStats& conn = it->second;
    
    // Update connection statistics
    conn.last_seen = metadata.timestamp;
    conn.duration = conn.last_seen - conn.start_time;
    
    // Update byte statistics and packet size statistics
    if (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p) {
        // Packet from source (upstream)
        conn.upstream_bytes += metadata.payload_length;
        conn.upstream_ip_bytes += metadata.packet_length;
        conn.upstream_pkts++;
        updatePacketSizeStats(conn.upstream_stats, metadata.packet_length);
        updatePacketIatStats(conn.upstream_iat_stats, metadata.timestamp);
        
        // Calculate and update control field statistics (header bytes = packet_length - payload_length)
        uint32_t control_field_size = metadata.packet_length - metadata.payload_length;
        updateControlFieldStats(conn.upstream_control_stats, control_field_size);
    } else {
        // Packet from response (downstream)
        conn.downstream_bytes += metadata.payload_length;
        conn.downstream_ip_bytes += metadata.packet_length;
        conn.downstream_pkts++;
        updatePacketSizeStats(conn.downstream_stats, metadata.packet_length);
        updatePacketIatStats(conn.downstream_iat_stats, metadata.timestamp);
        
        // Calculate and update control field statistics (header bytes = packet_length - payload_length)
        uint32_t control_field_size = metadata.packet_length - metadata.payload_length;
        updateControlFieldStats(conn.downstream_control_stats, control_field_size);
    }
    
    // Update connection state and history
    updateConnectionState(conn, metadata);
    updateConnectionHistory(conn, metadata);
    
    // Update TCP features if this is a TCP packet
    if (metadata.has_tcp) {
        updateTCPFeatures(conn, metadata);
    }
    
    // Update flow features
    updateTimeSinceLastConnection(conn, metadata);
    updateBulkModeTracking(conn, metadata);
    
    // Handle UDP flow timeout management
    if (conn.proto == "UDP") {
        double current_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() / 1000000.0;
        
        // Update UDP timeout (this will reset the timeout)
        updateUDPTimeout(conn_key, current_time);
        
        // Flush any expired UDP flows
        flushExpiredUDPFlows(current_time);
    } else {
        // For non-UDP protocols, check completion using traditional method
        // Calculate final statistics for upstream and downstream before checking
        calculatePacketSizeStats(conn.upstream_stats);
        calculatePacketSizeStats(conn.downstream_stats);
        calculatePacketIatStats(conn.upstream_iat_stats);
        calculatePacketIatStats(conn.downstream_iat_stats);
        calculateOverallFlowFFT(conn);
        calculateControlFieldStats(conn.upstream_control_stats);
        calculateControlFieldStats(conn.downstream_control_stats);
        calculateRTTStats(conn.upstream_rtt_stats);
        calculateRTTStats(conn.downstream_rtt_stats);
        
        if (isConnectionCompleted(conn)) {
            // Finalize bulk mode tracking before completing connection
            finalizeBulkModeTracking(conn);
            
            // Move completed connection to completed queue
            {
                std::lock_guard<std::mutex> completed_lock(completed_connections_mutex_);
                completed_connections_.push_back(conn);
            }
            // Remove from active connections
            connections_.erase(it);
        }
    }
}

std::vector<ConnectionStats> ConnectionTracker::getAllConnections() const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    std::vector<ConnectionStats> result;
    
    for (const auto& pair : connections_) {
        result.push_back(pair.second);
    }
    
    return result;
}

std::vector<ConnectionStats> ConnectionTracker::getCompletedConnections() const {
    std::lock_guard<std::mutex> completed_lock(completed_connections_mutex_);
    return completed_connections_;
}

void ConnectionTracker::cleanupTimeoutConnections(double timeout_seconds) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    double current_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() / 1000000.0;
    
    // First, flush expired UDP flows using the timeout tree
    flushExpiredUDPFlows(current_time);
    
    // Then handle other protocols with general timeout
    auto it = connections_.begin();
    while (it != connections_.end()) {
        ConnectionStats& conn = it->second;
        
        // Skip UDP flows as they are handled by the timeout tree
        if (conn.proto == "UDP") {
            ++it;
            continue;
        }
        
        // For non-UDP protocols, use general timeout
        if ((current_time - conn.last_seen) > timeout_seconds) {
            // Calculate final statistics before removing
            calculatePacketSizeStats(conn.upstream_stats);
            calculatePacketSizeStats(conn.downstream_stats);
            calculatePacketIatStats(conn.upstream_iat_stats);
            calculatePacketIatStats(conn.downstream_iat_stats);
            calculateOverallFlowFFT(conn);
            calculateControlFieldStats(conn.upstream_control_stats);
            calculateControlFieldStats(conn.downstream_control_stats);
            calculateRTTStats(conn.upstream_rtt_stats);
            calculateRTTStats(conn.downstream_rtt_stats);
            
            // Finalize bulk mode tracking
            finalizeBulkModeTracking(conn);
            
            // Move to completed connections if it's a valid flow
            if (conn.upstream_pkts > 0 || conn.downstream_pkts > 0) {
                std::lock_guard<std::mutex> completed_lock(completed_connections_mutex_);
                completed_connections_.push_back(conn);
            }
            
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

bool ConnectionTracker::isConnectionCompleted(const ConnectionStats& conn) const {
    // TCP connections are completed when they have FIN or RST flags
    if (conn.proto == "TCP") {
        return conn.fin_seen || conn.rst_seen;
    }
    
    // UDP flows are now managed by the timeout tree, not checked here
    // This method is only used for non-UDP protocols now
    
    // ICMP is considered completed immediately after seeing packets
    // This is a simple heuristic for ICMP
    if (conn.proto == "ICMP") {
        return (conn.upstream_pkts > 0 || conn.downstream_pkts > 0);
    }
    
    return false;
}

std::vector<ConnectionStats> ConnectionTracker::getAndRemoveCompletedConnections() {
    std::lock_guard<std::mutex> completed_lock(completed_connections_mutex_);
    std::vector<ConnectionStats> completed_connections = std::move(completed_connections_);
    completed_connections_.clear();
    return completed_connections;
}

void ConnectionTracker::setUDPFlowTimeout(double timeout_seconds) {
    udp_flow_timeout_ = timeout_seconds;
}

void ConnectionTracker::updateUDPTimeout(const std::string& connection_key, double current_time) {
    std::lock_guard<std::mutex> timeout_lock(udp_timeout_mutex_);
    
    // Remove existing timeout entry if it exists
    removeUDPTimeout(connection_key);
    
    // Calculate timeout time in nanoseconds
    uint64_t current_nanoseconds = static_cast<uint64_t>(current_time * 1000000000ULL);
    uint64_t timeout_nanoseconds = current_nanoseconds + static_cast<uint64_t>(udp_flow_timeout_ * 1000000000ULL);
    
    // Create unique timeout key
    UDPTimeoutKey timeout_key(timeout_nanoseconds, ++timeout_sequence_counter_);
    
    // Add new timeout entry to both mappings
    udp_timeout_tree_[timeout_key] = connection_key;
    udp_connection_to_timeout_[connection_key] = timeout_key;
}

void ConnectionTracker::removeUDPTimeout(const std::string& connection_key) {
    // Find the timeout key using reverse mapping (O(log n))
    auto reverse_it = udp_connection_to_timeout_.find(connection_key);
    if (reverse_it != udp_connection_to_timeout_.end()) {
        UDPTimeoutKey timeout_key = reverse_it->second;
        
        // Remove from timeout tree using the found key (O(log n))
        udp_timeout_tree_.erase(timeout_key);
        
        // Remove from reverse mapping (O(log n))
        udp_connection_to_timeout_.erase(reverse_it);
    }
}

void ConnectionTracker::flushExpiredUDPFlows(double current_time) {
    std::lock_guard<std::mutex> timeout_lock(udp_timeout_mutex_);
    std::vector<std::string> expired_connections;
    
    // Convert current time to nanoseconds for comparison
    uint64_t current_nanoseconds = static_cast<uint64_t>(current_time * 1000000000ULL);
    
    // Find all expired UDP flows using upper_bound for O(log u) positioning
    UDPTimeoutKey current_key(current_nanoseconds, UINT64_MAX);
    auto first_non_expired = udp_timeout_tree_.upper_bound(current_key);
    
    // Collect expired connections and remove from reverse mapping
    for (auto it = udp_timeout_tree_.begin(); it != first_non_expired; ++it) {
        expired_connections.push_back(it->second);
        udp_connection_to_timeout_.erase(it->second);  // O(log u)
    }
    
    // Batch remove all expired entries from timeout tree
    udp_timeout_tree_.erase(udp_timeout_tree_.begin(), first_non_expired);  // O(k + log u)
    
    // Process expired connections
    if (!expired_connections.empty()) {
        std::lock_guard<std::mutex> conn_lock(connections_mutex_);
        for (const auto& conn_key : expired_connections) {
            auto it = connections_.find(conn_key);
            if (it != connections_.end()) {
                ConnectionStats& conn = it->second;
                
                // Calculate final statistics before removing
                calculatePacketSizeStats(conn.upstream_stats);
                calculatePacketSizeStats(conn.downstream_stats);
                calculatePacketIatStats(conn.upstream_iat_stats);
                calculatePacketIatStats(conn.downstream_iat_stats);
                calculateOverallFlowFFT(conn);
                calculateControlFieldStats(conn.upstream_control_stats);
                calculateControlFieldStats(conn.downstream_control_stats);
                calculateRTTStats(conn.upstream_rtt_stats);
                calculateRTTStats(conn.downstream_rtt_stats);
                
                // Finalize bulk mode tracking
                finalizeBulkModeTracking(conn);
                
                // Move to completed connections if it's a valid flow
                if (conn.upstream_pkts > 0 || conn.downstream_pkts > 0) {
                    std::lock_guard<std::mutex> completed_lock(completed_connections_mutex_);
                    completed_connections_.push_back(conn);
                }
                
                // Remove from active connections
                connections_.erase(it);
            }
        }
    }
}

std::string ConnectionTracker::generateConnectionUID(const std::string& src_ip, uint16_t src_port,
                                                   const std::string& dst_ip, uint16_t dst_port,
                                                   const std::string& protocol) {
    std::ostringstream oss;
    oss << "C" << std::hex << std::setfill('0') << std::setw(8) << connection_counter_++;
    
    // Add random characters
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 10; ++i) {
        oss << charset[rand() % (sizeof(charset) - 1)];
    }
    
    return oss.str();
}

std::string ConnectionTracker::connectionStateToString(ConnectionState state) {
    switch (state) {
        case ConnectionState::S0: return "S0";
        case ConnectionState::S1: return "S1";
        case ConnectionState::SF: return "SF";
        case ConnectionState::REJ: return "REJ";
        case ConnectionState::S2: return "S2";
        case ConnectionState::S3: return "S3";
        case ConnectionState::RSTO: return "RSTO";
        case ConnectionState::RSTR: return "RSTR";
        case ConnectionState::RSTOS0: return "RSTOS0";
        case ConnectionState::RSTRH: return "RSTRH";
        case ConnectionState::SH: return "SH";
        case ConnectionState::SHR: return "SHR";
        case ConnectionState::OTH: return "OTH";
        default: return "UNKNOWN";
    }
}

std::string ConnectionTracker::detectService(const std::string& protocol, uint16_t port) {
    if (protocol == "TCP") {
        switch (port) {
            case 21: return "ftp";
            case 22: return "ssh";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "dns";
            case 80: return "http";
            case 110: return "pop3";
            case 143: return "imap";
            case 443: return "ssl";
            case 993: return "imaps";
            case 995: return "pop3s";
            case 3389: return "rdp";
            default: return "";
        }
    } else if (protocol == "UDP") {
        switch (port) {
            case 53: return "dns";
            case 67: return "dhcp";
            case 68: return "dhcp";
            case 123: return "ntp";
            case 161: return "snmp";
            case 162: return "snmp";
            case 514: return "syslog";
            default: return "";
        }
    } else if (protocol == "ICMP") {
        return "icmp";
    }
    
    return "";
}

std::string ConnectionTracker::generateConnectionKey(const std::string& src_ip, uint16_t src_port,
                                                    const std::string& dst_ip, uint16_t dst_port,
                                                    const std::string& protocol) {
    // Create normalized connection key (always sorted by IP address)
    std::string ip1, ip2;
    uint16_t port1, port2;
    
    if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
        ip1 = src_ip;
        port1 = src_port;
        ip2 = dst_ip;
        port2 = dst_port;
    } else {
        ip1 = dst_ip;
        port1 = dst_port;
        ip2 = src_ip;
        port2 = src_port;
    }
    
    std::ostringstream oss;
    oss << protocol << ":" << ip1 << ":" << port1 << ":" << ip2 << ":" << port2;
    return oss.str();
}

void ConnectionTracker::updateConnectionState(ConnectionStats& conn, const PacketMetadata& metadata) {
    if (conn.proto == "TCP") {
        conn.conn_state = detectTCPState(conn);
    } else if (conn.proto == "UDP") {
        conn.conn_state = detectUDPState(conn);
    } else if (conn.proto == "ICMP") {
        conn.conn_state = detectICMPState(conn);
    }
}

void ConnectionTracker::updateConnectionHistory(ConnectionStats& conn, const PacketMetadata& metadata) {
    char flag = '\0';
    bool is_originator = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    
    if (conn.proto == "TCP" && metadata.has_tcp) {
        if (metadata.tcp.syn && !metadata.tcp.ack_flag) {
            flag = 's';  // SYN without ACK
            conn.syn_seen = true;
        } else if (metadata.tcp.syn && metadata.tcp.ack_flag) {
            flag = 'h';  // SYN+ACK
            conn.syn_ack_seen = true;
        } else if (metadata.tcp.ack_flag && !metadata.tcp.syn && !metadata.tcp.fin && !metadata.tcp.rst) {
            flag = 'a';  // Pure ACK
            conn.ack_seen = true;
        } else if (metadata.tcp.fin) {
            flag = 'f';  // FIN
            conn.fin_seen = true;
        } else if (metadata.tcp.rst) {
            flag = 'r';  // RST
            conn.rst_seen = true;
        } else if (metadata.payload_length > 0) {
            flag = 'd';  // Data
            conn.data_seen = true;
        }
    } else if (conn.proto == "UDP" && metadata.has_udp) {
        if (metadata.payload_length > 0) {
            flag = 'd';  // Data
            conn.data_seen = true;
        }
    } else if (conn.proto == "ICMP" && metadata.has_icmp) {
        if (metadata.payload_length > 0) {
            flag = 'd';  // Data
            conn.data_seen = true;
        }
    }
    
    if (flag != '\0') {
        // Determine case based on direction
        char history_flag = is_originator ? std::toupper(flag) : std::tolower(flag);
        
        // Check if this flag has already been recorded
        if (conn.history.seen_flags.find(history_flag) == conn.history.seen_flags.end()) {
            conn.history.history += history_flag;
            conn.history.seen_flags.insert(history_flag);
        }
        
        // Update flag count (for log records)
        conn.history.flag_counts[history_flag]++;
    }
}

ConnectionState ConnectionTracker::detectTCPState(const ConnectionStats& conn) {
    if (!conn.syn_seen && !conn.syn_ack_seen) {
        return ConnectionState::OTH;  // No SYN seen
    }
    
    if (conn.syn_seen && !conn.syn_ack_seen && !conn.fin_seen && !conn.rst_seen) {
        return ConnectionState::S0;  // Connection attempt seen, no reply
    }
    
    if (conn.syn_seen && conn.syn_ack_seen && !conn.fin_seen && !conn.rst_seen) {
        return ConnectionState::S1;  // Connection established, not terminated
    }
    
    if (conn.syn_seen && conn.syn_ack_seen && conn.fin_seen && !conn.rst_seen) {
        return ConnectionState::SF;  // Normal establishment and termination
    }
    
    if (conn.rst_seen) {
        if (conn.syn_seen && !conn.syn_ack_seen) {
            return ConnectionState::RSTOS0;  // SYN followed by RST
        } else if (conn.syn_ack_seen && !conn.syn_seen) {
            return ConnectionState::RSTRH;  // SYN-ACK followed by RST
        } else if (conn.syn_seen && conn.syn_ack_seen) {
            return ConnectionState::RSTO;  // Connection established, originator aborted
        } else {
            return ConnectionState::RSTR;  // Responder sent RST
        }
    }
    
    if (conn.syn_seen && conn.fin_seen && !conn.syn_ack_seen) {
        return ConnectionState::SH;  // SYN followed by FIN
    }
    
    if (conn.syn_ack_seen && conn.fin_seen && !conn.syn_seen) {
        return ConnectionState::SHR;  // SYN-ACK followed by FIN
    }
    
    return ConnectionState::OTH;
}

ConnectionState ConnectionTracker::detectUDPState(const ConnectionStats& conn) {
    // UDP is a connectionless protocol, usually SF state
    if (conn.upstream_pkts > 0 || conn.downstream_pkts > 0) {
        return ConnectionState::SF;
    }
    return ConnectionState::OTH;
}

ConnectionState ConnectionTracker::detectICMPState(const ConnectionStats& conn) {
    // ICMP is a connectionless protocol, usually SF state
    if (conn.upstream_pkts > 0 || conn.downstream_pkts > 0) {
        return ConnectionState::SF;
    }
    return ConnectionState::OTH;
}

std::string ConnectionTracker::generateHistoryString(const ConnectionHistory& history) {
    return history.history;
}

void ConnectionTracker::updatePacketSizeStats(PacketSizeStats& stats, uint32_t packet_size) {
    stats.packet_sizes.push_back(packet_size);
    stats.total_bytes += packet_size;
    stats.packet_count++;
    
    // Update min and max packet sizes
    if (stats.packet_count == 1) {
        stats.min_size = packet_size;
        stats.max_size = packet_size;
    } else {
        if (packet_size < stats.min_size) {
            stats.min_size = packet_size;
        }
        if (packet_size > stats.max_size) {
            stats.max_size = packet_size;
        }
    }
    
    // Calculate average packet size
    stats.avg_size = static_cast<double>(stats.total_bytes) / stats.packet_count;
}

void ConnectionTracker::updatePacketIatStats(PacketIatStats& stats, double timestamp_seconds) {
    // Handle inter-arrival time calculation
    if (stats.last_timestamp > 0.0) {
        // Calculate inter-arrival time (time difference between consecutive packets in seconds)
        double interarrival_time = timestamp_seconds - stats.last_timestamp;
        
        // Only record positive inter-arrival times (handle clock issues)
        if (interarrival_time > 0.0) {
            stats.iat_times.push_back(interarrival_time);
            stats.iat_count++;
            
            // Update min and max inter-arrival times
            if (stats.iat_times.size() == 1) {
                stats.min_iat = interarrival_time;
                stats.max_iat = interarrival_time;
            } else {
                if (interarrival_time < stats.min_iat) {
                    stats.min_iat = interarrival_time;
                }
                if (interarrival_time > stats.max_iat) {
                    stats.max_iat = interarrival_time;
                }
            }
            
            // Calculate average inter-arrival time
            double total_iat = 0.0;
            for (double time : stats.iat_times) {
                total_iat += time;
            }
            stats.avg_iat = total_iat / stats.iat_times.size();
        }
    }
    
    // Store timestamp for next packet
    stats.last_timestamp = timestamp_seconds;
}

void ConnectionTracker::updateControlFieldStats(ControlFieldStats& stats, uint32_t control_field_size) {
    stats.control_field_sizes.push_back(control_field_size);
    stats.total_control_bytes += control_field_size;
    stats.packet_count++;
    
    // Update min and max control field sizes
    if (stats.packet_count == 1) {
        stats.min_control_size = control_field_size;
        stats.max_control_size = control_field_size;
    } else {
        if (control_field_size < stats.min_control_size) {
            stats.min_control_size = control_field_size;
        }
        if (control_field_size > stats.max_control_size) {
            stats.max_control_size = control_field_size;
        }
    }
    
    // Calculate average control field size
    stats.avg_control_size = static_cast<double>(stats.total_control_bytes) / stats.packet_count;
}

void ConnectionTracker::calculatePacketSizeStats(PacketSizeStats& stats) const {
    if (stats.packet_sizes.empty()) {
        return;
    }
    
    // Calculate packet size statistics
    calculateSizeStatistics(stats);
}

void ConnectionTracker::calculatePacketIatStats(PacketIatStats& stats) const {
    if (stats.iat_times.empty()) {
        return;
    }
    
    // Calculate inter-arrival time statistics
    calculateIatStatistics(stats);
    
    // Calculate FFT features
    calculateFFTFeatures(stats);
}

void ConnectionTracker::calculateControlFieldStats(ControlFieldStats& stats) const {
    if (stats.control_field_sizes.empty()) {
        return;
    }
    
    // Calculate control field statistics
    calculateControlFieldStatistics(stats);
}

void ConnectionTracker::calculateSizeStatistics(PacketSizeStats& stats) const {
    if (stats.packet_sizes.empty()) {
        return;
    }
    
    std::vector<uint32_t> sorted_sizes = stats.packet_sizes;
    std::sort(sorted_sizes.begin(), sorted_sizes.end());
    
    size_t size = sorted_sizes.size();
    
    // Calculate median (Q2)
    if (size % 2 == 0) {
        stats.median_size = (sorted_sizes[size / 2 - 1] + sorted_sizes[size / 2]) / 2.0;
    } else {
        stats.median_size = sorted_sizes[size / 2];
    }
    
    // Calculate first quartile (Q1) - 25th percentile
    size_t q1_index = size / 4;
    if (size % 4 == 0) {
        stats.first_quartile = (sorted_sizes[q1_index - 1] + sorted_sizes[q1_index]) / 2.0;
    } else {
        stats.first_quartile = sorted_sizes[q1_index];
    }
    
    // Calculate third quartile (Q3) - 75th percentile
    size_t q3_index = (3 * size) / 4;
    if ((3 * size) % 4 == 0) {
        stats.third_quartile = (sorted_sizes[q3_index - 1] + sorted_sizes[q3_index]) / 2.0;
    } else {
        stats.third_quartile = sorted_sizes[q3_index];
    }
    
    // Calculate skewness and kurtosis for packet sizes
    if (size >= 3) {  // Need at least 3 samples for meaningful statistics
        // Convert uint32_t to double for calculation
        std::vector<double> double_sizes(stats.packet_sizes.begin(), stats.packet_sizes.end());
        calculateSkewnessAndKurtosis(double_sizes, stats.avg_size, stats.size_skewness, stats.size_kurtosis);
    }
}

void ConnectionTracker::calculateIatStatistics(PacketIatStats& stats) const {
    if (stats.iat_times.empty()) {
        return;
    }
    
    std::vector<double> sorted_times = stats.iat_times;
    std::sort(sorted_times.begin(), sorted_times.end());
    
    size_t size = sorted_times.size();
    
    // Calculate median
    if (size % 2 == 0) {
        stats.median_iat = (sorted_times[size / 2 - 1] + sorted_times[size / 2]) / 2.0;
    } else {
        stats.median_iat = sorted_times[size / 2];
    }
    
    // Calculate first quartile (Q1)
    size_t q1_index = size / 4;
    if (size % 4 == 0) {
        stats.first_quartile_iat = (sorted_times[q1_index - 1] + sorted_times[q1_index]) / 2.0;
    } else {
        stats.first_quartile_iat = sorted_times[q1_index];
    }
    
    // Calculate third quartile (Q3)
    size_t q3_index = (3 * size) / 4;
    if ((3 * size) % 4 == 0) {
        stats.third_quartile_iat = (sorted_times[q3_index - 1] + sorted_times[q3_index]) / 2.0;
    } else {
        stats.third_quartile_iat = sorted_times[q3_index];
    }
    
    // Calculate skewness and kurtosis for inter-arrival times
    if (size >= 3) {
        calculateSkewnessAndKurtosis(stats.iat_times, stats.avg_iat, 
                                   stats.iat_skewness, stats.iat_kurtosis);
    }
}

void ConnectionTracker::calculateControlFieldStatistics(ControlFieldStats& stats) const {
    if (stats.control_field_sizes.empty()) {
        return;
    }
    
    std::vector<uint32_t> sorted_sizes = stats.control_field_sizes;
    std::sort(sorted_sizes.begin(), sorted_sizes.end());
    
    size_t size = sorted_sizes.size();
    
    // Calculate median (Q2)
    if (size % 2 == 0) {
        stats.median_control_size = (sorted_sizes[size / 2 - 1] + sorted_sizes[size / 2]) / 2.0;
    } else {
        stats.median_control_size = sorted_sizes[size / 2];
    }
    
    // Calculate first quartile (Q1) - 25th percentile
    size_t q1_index = size / 4;
    if (size % 4 == 0) {
        stats.first_quartile = (sorted_sizes[q1_index - 1] + sorted_sizes[q1_index]) / 2.0;
    } else {
        stats.first_quartile = sorted_sizes[q1_index];
    }
    
    // Calculate third quartile (Q3) - 75th percentile
    size_t q3_index = (3 * size) / 4;
    if ((3 * size) % 4 == 0) {
        stats.third_quartile = (sorted_sizes[q3_index - 1] + sorted_sizes[q3_index]) / 2.0;
    } else {
        stats.third_quartile = sorted_sizes[q3_index];
    }
    
    // Calculate skewness and kurtosis for control field sizes
    if (size >= 3) {  // Need at least 3 samples for meaningful statistics
        // Convert uint32_t to double for calculation
        std::vector<double> double_sizes(stats.control_field_sizes.begin(), stats.control_field_sizes.end());
        calculateSkewnessAndKurtosis(double_sizes, stats.avg_control_size, stats.control_skewness, stats.control_kurtosis);
    }
}

void ConnectionTracker::calculateSkewnessAndKurtosis(const std::vector<double>& data, double mean, 
                                                    double& skewness, double& kurtosis) const {
    if (data.size() < 3) {
        skewness = 0.0;
        kurtosis = 0.0;
        return;
    }
    
    size_t n = data.size();
    double sum_squared_diff = 0.0;
    double sum_cubed_diff = 0.0;
    double sum_fourth_diff = 0.0;
    
    // Calculate moments
    for (double value : data) {
        double diff = value - mean;
        double diff_squared = diff * diff;
        sum_squared_diff += diff_squared;
        sum_cubed_diff += diff_squared * diff;
        sum_fourth_diff += diff_squared * diff_squared;
    }
    
    // Calculate variance (sample variance)
    double variance = sum_squared_diff / (n - 1);
    double std_dev = std::sqrt(variance);
    
    if (std_dev == 0.0) {
        skewness = 0.0;
        kurtosis = 0.0;
        return;
    }
    
    // Calculate skewness (third moment)
    double third_moment = sum_cubed_diff / n;
    skewness = third_moment / (std_dev * std_dev * std_dev);
    
    // Calculate kurtosis (fourth moment)
    double fourth_moment = sum_fourth_diff / n;
    kurtosis = (fourth_moment / (std_dev * std_dev * std_dev * std_dev)) - 3.0;  // Excess kurtosis
}

void ConnectionTracker::updateTCPFeatures(ConnectionStats& conn, const PacketMetadata& metadata) {
    if (!metadata.has_tcp) {
        return;
    }
    
    bool is_upstream = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    
    // Update sequence tracking
    updateSequenceTracking(conn, metadata);
    
    // Update RTT tracking
    updateRTTTracking(conn, metadata);
    
    // Check for PUSH bit
    if (metadata.tcp.psh) {
        if (is_upstream) {
            conn.up_pushed_data_pkts++;
        } else {
            conn.down_pushed_data_pkts++;
        }
    }
    
    // Check for SYN bit
    if (metadata.tcp.syn) {
        if (is_upstream) {
            conn.up_syn_pkts++;
        } else {
            conn.down_syn_pkts++;
        }
    }
    
    // Check for FIN bit
    if (metadata.tcp.fin) {
        if (is_upstream) {
            conn.up_fin_pkts++;
        } else {
            conn.down_fin_pkts++;
        }
    }
    
    // Check for ACK packets
    if (metadata.tcp.ack_flag) {
        if (is_upstream) {
            conn.up_ack_pkts++;
        } else {
            conn.down_ack_pkts++;
        }
        
        // Check for pure ACK (ACK without data and without SYN/FIN/RST)
        if (isPureACK(metadata)) {
            if (is_upstream) {
                conn.up_pure_acks++;
            } else {
                conn.down_pure_acks++;
            }
        }
        
        // Check for SACK
        if (hasSACK(metadata)) {
            if (is_upstream) {
                conn.up_sack_pkts++;
                uint32_t sack_blocks = getSACKBlockCount(metadata);
                if (sack_blocks > conn.up_max_sack_blks) {
                    conn.up_max_sack_blks = sack_blocks;
                }
            } else {
                conn.down_sack_pkts++;
                uint32_t sack_blocks = getSACKBlockCount(metadata);
                if (sack_blocks > conn.down_max_sack_blks) {
                    conn.down_max_sack_blks = sack_blocks;
                }
            }
            
            // Check for D-SACK
            if (hasDSACK(metadata)) {
                if (is_upstream) {
                    conn.up_dsack_pkts++;
                } else {
                    conn.down_dsack_pkts++;
                }
            }
        }
    }
    
    // Check for data packets
    if (metadata.payload_length > 0) {
        if (is_upstream) {
            conn.up_actual_data_pkts++;
            conn.up_actual_data_bytes += metadata.payload_length;
            
            // Check for retransmission
            if (isRetransmission(conn, metadata)) {
                conn.up_rexmt_data_pkts++;
                conn.up_rexmt_data_bytes += metadata.payload_length;
            } else {
                // Only count as unique bytes if not a retransmission
                conn.up_unique_bytes += metadata.payload_length;
            }
            
            // Check for zero window probe
            if (isZeroWindowProbe(conn, metadata)) {
                conn.up_zwnd_probe_pkts++;
                conn.up_zwnd_probe_bytes += metadata.payload_length;
            }
        } else {
            conn.down_actual_data_pkts++;
            conn.down_actual_data_bytes += metadata.payload_length;
            
            // Check for retransmission
            if (isRetransmission(conn, metadata)) {
                conn.down_rexmt_data_pkts++;
                conn.down_rexmt_data_bytes += metadata.payload_length;
            } else {
                // Only count as unique bytes if not a retransmission
                conn.down_unique_bytes += metadata.payload_length;
            }
            
            // Check for zero window probe
            if (isZeroWindowProbe(conn, metadata)) {
                conn.down_zwnd_probe_pkts++;
                conn.down_zwnd_probe_bytes += metadata.payload_length;
            }
        }
    }
}

bool ConnectionTracker::isPureACK(const PacketMetadata& metadata) const {
    if (!metadata.has_tcp) {
        return false;
    }
    
    // Pure ACK: has ACK flag, no data payload, and no SYN/FIN/RST flags
    return metadata.tcp.ack_flag && 
           metadata.payload_length == 0 && 
           !metadata.tcp.syn && 
           !metadata.tcp.fin && 
           !metadata.tcp.rst;
}

bool ConnectionTracker::hasSACK(const PacketMetadata& metadata) const {
    if (!metadata.has_tcp) {
        return false;
    }
    
    // This is a simplified check - in reality, we would need to parse TCP options
    // For now, we'll assume SACK is present if the packet has ACK flag and payload
    // In a real implementation, you would parse the TCP options field
    return metadata.tcp.ack_flag && metadata.payload_length > 0;
}

bool ConnectionTracker::hasDSACK(const PacketMetadata& metadata) const {
    if (!metadata.has_tcp) {
        return false;
    }
    
    // This is a simplified check - in reality, we would need to parse TCP SACK options
    // and check if any SACK block covers data that was already acknowledged
    // For now, we'll return false as a placeholder
    return false;
}

uint32_t ConnectionTracker::getSACKBlockCount(const PacketMetadata& metadata) const {
    if (!metadata.has_tcp) {
        return 0;
    }
    
    // This is a simplified implementation - in reality, we would need to parse TCP options
    // For now, we'll return a placeholder value
    return 0;
}

bool ConnectionTracker::isRetransmission(ConnectionStats& conn, const PacketMetadata& metadata) const {
    if (!metadata.has_tcp) {
        return false;
    }
    
    bool is_upstream = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    
    if (is_upstream) {
        if (!conn.up_seq_initialized) {
            return false;
        }
        // Check if sequence number is less than the last seen sequence number (indicating retransmission)
        return metadata.tcp.seq < conn.up_last_seq;
    } else {
        if (!conn.down_seq_initialized) {
            return false;
        }
        // Check if sequence number is less than the last seen sequence number (indicating retransmission)
        return metadata.tcp.seq < conn.down_last_seq;
    }
}

bool ConnectionTracker::isZeroWindowProbe(ConnectionStats& conn, const PacketMetadata& metadata) const {
    if (!metadata.has_tcp) {
        return false;
    }
    
    // Zero window probe: small data packet (typically 1 byte) with PSH flag
    // This is a simplified check - in reality, we would need to track window sizes
    return metadata.tcp.psh && metadata.payload_length == 1;
}

void ConnectionTracker::updateSequenceTracking(ConnectionStats& conn, const PacketMetadata& metadata) {
    if (!metadata.has_tcp) {
        return;
    }
    
    bool is_upstream = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    
    if (is_upstream) {
        if (!conn.up_seq_initialized) {
            conn.up_last_seq = metadata.tcp.seq;
            conn.up_expected_seq = metadata.tcp.seq + metadata.payload_length;
            conn.up_seq_initialized = true;
        } else {
            // Update sequence tracking
            if (metadata.payload_length > 0) {
                // Out-of-order detection: data segment with seq greater than expected (gap seen)
                if (metadata.tcp.seq > conn.up_expected_seq) {
                    conn.up_out_of_order_pkts++;
                }
                conn.up_last_seq = metadata.tcp.seq;
                conn.up_expected_seq = metadata.tcp.seq + metadata.payload_length;
            }
        }
        conn.up_last_ack = metadata.tcp.ack;
    } else {
        if (!conn.down_seq_initialized) {
            conn.down_last_seq = metadata.tcp.seq;
            conn.down_expected_seq = metadata.tcp.seq + metadata.payload_length;
            conn.down_seq_initialized = true;
        } else {
            // Update sequence tracking
            if (metadata.payload_length > 0) {
                // Out-of-order detection: data segment with seq greater than expected (gap seen)
                if (metadata.tcp.seq > conn.down_expected_seq) {
                    conn.down_out_of_order_pkts++;
                }
                conn.down_last_seq = metadata.tcp.seq;
                conn.down_expected_seq = metadata.tcp.seq + metadata.payload_length;
            }
        }
        conn.down_last_ack = metadata.tcp.ack;
    }
}

void ConnectionTracker::updateRTTTracking(ConnectionStats& conn, const PacketMetadata& metadata) {
    if (!metadata.has_tcp) {
        return;
    }
    
    bool is_upstream = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    
    if (is_upstream) {
        // Track upstream data packets for RTT calculation
        if (metadata.payload_length > 0) {
            RTTTrackingInfo tracking_info;
            tracking_info.seq_num = metadata.tcp.seq;
            tracking_info.payload_length = metadata.payload_length;
            tracking_info.timestamp = metadata.timestamp;
            tracking_info.is_retransmitted = isRetransmission(conn, metadata);
            tracking_info.acked = false;
            
            // Store tracking info for this sequence number
            conn.up_rtt_tracking[metadata.tcp.seq] = tracking_info;
            
        }
    } else {
        // Track downstream data packets for RTT calculation
        if (metadata.payload_length > 0) {
            RTTTrackingInfo tracking_info;
            tracking_info.seq_num = metadata.tcp.seq;
            tracking_info.payload_length = metadata.payload_length;
            tracking_info.timestamp = metadata.timestamp;
            tracking_info.is_retransmitted = isRetransmission(conn, metadata);
            tracking_info.acked = false;
            
            // Store tracking info for this sequence number
            conn.down_rtt_tracking[metadata.tcp.seq] = tracking_info;
            
        }
    }
    
    // Process ACK packets for RTT calculation (both directions)
    if (metadata.tcp.ack_flag) {
        processRTTACK(conn, metadata);
    }
}

void ConnectionTracker::processRTTACK(ConnectionStats& conn, const PacketMetadata& metadata) {
    if (!metadata.has_tcp) {
        return;
    }
    
    bool is_upstream = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    uint32_t ack_num = metadata.tcp.ack;
    
    if (is_upstream) {
        // Process upstream ACK (acknowledging downstream data)
        // Look for downstream packets that are being acknowledged
        for (auto it = conn.down_rtt_tracking.begin(); it != conn.down_rtt_tracking.end();) {
            const RTTTrackingInfo& tracking_info = it->second;
            
            // Check if this ACK acknowledges the packet
            // ACK number should be >= sequence number + payload length of the packet being acknowledged
            uint32_t expected_ack = tracking_info.seq_num + tracking_info.payload_length;
            if (ack_num >= expected_ack && !tracking_info.acked) {
                // This ACK acknowledges the packet
                if (isValidRTTSample(tracking_info, metadata)) {
                    // Calculate RTT: ACK timestamp - packet send timestamp
                    double rtt_value = metadata.timestamp - tracking_info.timestamp;
                    addRTTSample(conn.downstream_rtt_stats, rtt_value);
                }
                
                // Mark as acknowledged and remove from tracking
                it = conn.down_rtt_tracking.erase(it);
            } else {
                ++it;
            }
        }
    } else {
        // Process downstream ACK (acknowledging upstream data)
        // Look for upstream packets that are being acknowledged
        for (auto it = conn.up_rtt_tracking.begin(); it != conn.up_rtt_tracking.end();) {
            const RTTTrackingInfo& tracking_info = it->second;
            
            // Check if this ACK acknowledges the packet
            // ACK number should be >= sequence number + payload length of the packet being acknowledged
            uint32_t expected_ack = tracking_info.seq_num + tracking_info.payload_length;
            if (ack_num >= expected_ack && !tracking_info.acked) {
                // This ACK acknowledges the packet
                if (isValidRTTSample(tracking_info, metadata)) {
                    // Calculate RTT: ACK timestamp - packet send timestamp
                    double rtt_value = metadata.timestamp - tracking_info.timestamp;
                    addRTTSample(conn.upstream_rtt_stats, rtt_value);
                }
                
                // Mark as acknowledged and remove from tracking
                it = conn.up_rtt_tracking.erase(it);
            } else {
                ++it;
            }
        }
    }
}

bool ConnectionTracker::isValidRTTSample(const RTTTrackingInfo& tracking_info, const PacketMetadata& metadata) const {
    // According to tcptrace rules:
    // 1. The packet being acknowledged was not retransmitted
    // 2. No packets that came before it in the sequence space were retransmitted after the packet was transmitted
    
    // Rule 1: Packet must not be retransmitted
    if (tracking_info.is_retransmitted) {
        return false;
    }
    
    // Rule 2: Check if any packets before this one were retransmitted after this packet was sent
    // This is a simplified check - in a full implementation, we would need to track
    // the retransmission history more carefully
    
    // For now, we'll use a simplified validation
    // In practice, this would require more sophisticated tracking of retransmission patterns
    return true;
}

void ConnectionTracker::addRTTSample(RTTStats& stats, double rtt_value) {
    // Only add positive RTT values
    if (rtt_value <= 0.0) {
        return;
    }
    
    stats.rtt_samples.push_back(rtt_value);
    stats.rtt_count++;
    
    // Update min and max RTT
    if (stats.rtt_count == 1) {
        stats.min_rtt = rtt_value;
        stats.max_rtt = rtt_value;
    } else {
        if (rtt_value < stats.min_rtt) {
            stats.min_rtt = rtt_value;
        }
        if (rtt_value > stats.max_rtt) {
            stats.max_rtt = rtt_value;
        }
    }
    
    // Calculate average RTT
    double total_rtt = 0.0;
    for (double rtt : stats.rtt_samples) {
        total_rtt += rtt;
    }
    stats.avg_rtt = total_rtt / stats.rtt_samples.size();
}

void ConnectionTracker::calculateRTTStats(RTTStats& stats) const {
    if (stats.rtt_samples.empty()) {
        return;
    }
    
    // Calculate RTT statistics
    calculateRTTStatistics(stats);
}

void ConnectionTracker::calculateRTTStatistics(RTTStats& stats) const {
    if (stats.rtt_samples.empty()) {
        return;
    }
    
    std::vector<double> sorted_rtts = stats.rtt_samples;
    std::sort(sorted_rtts.begin(), sorted_rtts.end());
    
    size_t size = sorted_rtts.size();
    
    // Calculate median (Q2)
    if (size % 2 == 0) {
        stats.median_rtt = (sorted_rtts[size / 2 - 1] + sorted_rtts[size / 2]) / 2.0;
    } else {
        stats.median_rtt = sorted_rtts[size / 2];
    }
    
    // Calculate first quartile (Q1) - 25th percentile
    size_t q1_index = size / 4;
    if (size % 4 == 0) {
        stats.first_quartile_rtt = (sorted_rtts[q1_index - 1] + sorted_rtts[q1_index]) / 2.0;
    } else {
        stats.first_quartile_rtt = sorted_rtts[q1_index];
    }
    
    // Calculate third quartile (Q3) - 75th percentile
    size_t q3_index = (3 * size) / 4;
    if ((3 * size) % 4 == 0) {
        stats.third_quartile_rtt = (sorted_rtts[q3_index - 1] + sorted_rtts[q3_index]) / 2.0;
    } else {
        stats.third_quartile_rtt = sorted_rtts[q3_index];
    }
    
    // Calculate skewness and kurtosis for RTT values
    if (size >= 3) {
        calculateSkewnessAndKurtosis(stats.rtt_samples, stats.avg_rtt, 
                                   stats.rtt_skewness, stats.rtt_kurtosis);
    }
}

// Generate host pair key for tracking connections between host pairs
std::string ConnectionTracker::generateHostPairKey(const std::string& ip1, const std::string& ip2) {
    // Always use lexicographically smaller IP first to ensure consistent key
    if (ip1 < ip2) {
        return ip1 + ":" + ip2;
    } else {
        return ip2 + ":" + ip1;
    }
}

// Update time since last connection feature
void ConnectionTracker::updateTimeSinceLastConnection(ConnectionStats& conn, const PacketMetadata& metadata) {
    std::lock_guard<std::mutex> lock(host_pairs_mutex_);
    
    std::string host_pair_key = generateHostPairKey(conn.upstream_h, conn.downstream_h);
    
    auto it = host_pair_last_seen_.find(host_pair_key);
    if (it != host_pair_last_seen_.end()) {
        // Calculate time since last connection between these hosts
        conn.time_since_last_conn = metadata.timestamp - it->second;
    } else {
        // First connection between these hosts
        conn.time_since_last_conn = 0.0;
    }
    
    // Update last seen time for this host pair
    host_pair_last_seen_[host_pair_key] = metadata.timestamp;
}

// Update bulk mode tracking features
void ConnectionTracker::updateBulkModeTracking(ConnectionStats& conn, const PacketMetadata& metadata) {
    bool current_packet_is_upstream = (metadata.srcIP == conn.upstream_h && metadata.srcPort == conn.upstream_p);
    bool current_packet_has_data = (metadata.payload_length > 0);
    
    // Only process packets with data for bulk mode detection
    if (!current_packet_has_data) {
        return;
    }
    
    // Check if this is the first data packet
    if (!conn.last_packet_had_data) {
        conn.last_packet_direction_up = current_packet_is_upstream;
        conn.consecutive_same_dir_packets = 1;
        conn.last_packet_had_data = true;
        return;
    }
    
    // Check if packet direction changed
    if (conn.last_packet_direction_up != current_packet_is_upstream) {
        // Direction changed - check if we were in bulk mode
        if (conn.is_in_bulk_mode) {
            // Exiting bulk mode - add time spent
            conn.time_spent_in_bulk += (metadata.timestamp - conn.bulk_mode_start_time);
            conn.is_in_bulk_mode = false;
            conn.bulk_trans_transitions++;
        }
        
        // Reset consecutive packet count for new direction
        conn.consecutive_same_dir_packets = 1;
        conn.last_packet_direction_up = current_packet_is_upstream;
    } else {
        // Same direction as previous packet
        conn.consecutive_same_dir_packets++;
        
        // Check if we should enter bulk mode (3+ consecutive packets in same direction)
        if (conn.consecutive_same_dir_packets >= 3 && !conn.is_in_bulk_mode) {
            conn.is_in_bulk_mode = true;
            conn.bulk_mode_start_time = metadata.timestamp;
            conn.bulk_trans_transitions++;
        }
    }
}

// Finalize bulk mode tracking when connection ends
void ConnectionTracker::finalizeBulkModeTracking(ConnectionStats& conn) {
    // If connection is still in bulk mode when it ends, finalize the time spent
    if (conn.is_in_bulk_mode) {
        conn.time_spent_in_bulk += (conn.last_seen - conn.bulk_mode_start_time);
        conn.is_in_bulk_mode = false;
    }
}

// Calculate FFT features for packet inter-arrival times
void ConnectionTracker::calculateFFTFeatures(PacketIatStats& stats) const {
    // Skip if already computed or not enough data
    if (stats.fft_computed || stats.iat_times.size() < 4) {
        return;
    }
    
    // Extract top 10 FFT features using the FFT analyzer
    stats.iat_fft_top_ten_features = fft_analyzer_.extractTopTenFeatures(stats.iat_times);
    stats.fft_computed = true;
}

// Calculate overall flow FFT analysis (combining all packets chronologically)
void ConnectionTracker::calculateOverallFlowFFT(ConnectionStats& conn) {
    // Skip if already computed AND we have enough data
    if (conn.flow_fft_computed && !conn.flow_iat_fft_top_ten_features.empty()) {
        return;
    }
    
    
    // Combine upstream and downstream IAT times in chronological order
    std::vector<std::pair<double, double>> timestamped_iats;
    
    // Add upstream IAT times with their timestamps
    double upstream_timestamp = conn.start_time;
    for (double iat : conn.upstream_iat_stats.iat_times) {
        upstream_timestamp += iat;
        timestamped_iats.emplace_back(upstream_timestamp, iat);
    }
    
    // Add downstream IAT times with their timestamps
    double downstream_timestamp = conn.start_time;
    for (double iat : conn.downstream_iat_stats.iat_times) {
        downstream_timestamp += iat;
        timestamped_iats.emplace_back(downstream_timestamp, iat);
    }
    
    
    
    // Sort by timestamp to get chronological order
    std::sort(timestamped_iats.begin(), timestamped_iats.end());
    
    // Extract just the IAT values in chronological order
    std::vector<double> chronological_iats;
    chronological_iats.reserve(timestamped_iats.size());
    for (const auto& pair : timestamped_iats) {
        chronological_iats.push_back(pair.second);
    }
    
    
    // Calculate FFT features if we have enough data (minimum 4 samples for meaningful FFT)
    if (chronological_iats.size() >= 4) {
        conn.flow_iat_fft_top_ten_features = fft_analyzer_.extractTopTenFeatures(chronological_iats);
    }
    
    conn.flow_fft_computed = true;
}
