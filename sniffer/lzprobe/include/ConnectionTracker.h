#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include <string>
#include <map>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <set>
#include <queue>
#include "PacketMetadata.h"
#include "utils/FFTAnalyzer.h"

// Connection state enumeration
enum class ConnectionState {
    S0,     // Connection attempt seen, no reply
    S1,     // Connection established, not terminated
    SF,     // Normal establishment and termination
    REJ,    // Connection attempt rejected
    S2,     // Connection established and close attempt by originator seen
    S3,     // Connection established and close attempt by responder seen
    RSTO,   // Connection established, originator aborted
    RSTR,   // Responder sent a RST
    RSTOS0, // Originator sent a SYN followed by a RST
    RSTRH,  // Responder sent a SYN ACK followed by a RST
    SH,     // Originator sent a SYN followed by a FIN
    SHR,    // Responder sent a SYN ACK followed by a FIN
    OTH     // No SYN seen, just midstream traffic
};

// Connection history record
struct ConnectionHistory {
    std::string history;  // Connection history string
    std::set<char> seen_flags;  // Flags that have been seen
    std::map<char, int> flag_counts;  // Flag counts (for log records)
};

// RTT statistics structure
struct RTTStats {
    std::vector<double> rtt_samples;    // Store RTT samples for statistical analysis
    uint32_t rtt_count;                 // Number of RTT samples
    double min_rtt;                     // Minimum RTT (seconds)
    double max_rtt;                     // Maximum RTT (seconds)
    double avg_rtt;                     // Average RTT (seconds)
    double median_rtt;                  // Median RTT (seconds)
    double first_quartile_rtt;          // First quartile RTT (seconds)
    double third_quartile_rtt;          // Third quartile RTT (seconds)
    
    // Higher-order statistics for RTT
    double rtt_skewness;                // Skewness of RTT values
    double rtt_kurtosis;                // Kurtosis of RTT values
    
    RTTStats() : rtt_count(0), min_rtt(0.0), max_rtt(0.0), avg_rtt(0.0),
                median_rtt(0.0), first_quartile_rtt(0.0), third_quartile_rtt(0.0),
                rtt_skewness(0.0), rtt_kurtosis(0.0) {}
};

// RTT tracking structure
struct RTTTrackingInfo {
    uint32_t seq_num;        // Sequence number of the packet
    uint32_t payload_length; // Payload length of the packet
    double timestamp;         // Timestamp when packet was sent
    bool is_retransmitted;   // Whether this packet was retransmitted
    bool acked;              // Whether this packet has been acknowledged
};

    // Packet size statistics for statistical analysis
    struct PacketSizeStats {
        std::vector<uint32_t> packet_sizes;  // Store packet sizes for statistical analysis
        uint64_t total_bytes;               // Total bytes
        uint32_t packet_count;              // Packet count
        uint32_t min_size;                  // Minimum packet size
        uint32_t max_size;                  // Maximum packet size
        double avg_size;                    // Average packet size
        double median_size;                 // Median packet size
        double first_quartile;              // First quartile (Q1) - 25th percentile
        double third_quartile;              // Third quartile (Q3) - 75th percentile
        
        // Higher-order statistics for packet sizes
        double size_skewness;               // Skewness of packet sizes
        double size_kurtosis;               // Kurtosis of packet sizes
        
        PacketSizeStats() : total_bytes(0), packet_count(0), min_size(0), max_size(0), 
                           avg_size(0.0), median_size(0.0), first_quartile(0.0), third_quartile(0.0),
                           size_skewness(0.0), size_kurtosis(0.0) {}
    };
    
    // Packet inter-arrival time statistics for statistical analysis
    struct PacketIatStats {
        std::vector<double> iat_times;    // Store inter-arrival times between packets (in seconds, 9 decimal precision)
        uint32_t iat_count;               // Number of inter-arrival times
        double min_iat;                   // Minimum inter-arrival time (seconds, 9 decimal precision)
        double max_iat;                   // Maximum inter-arrival time (seconds, 9 decimal precision)
        double avg_iat;                   // Average inter-arrival time (seconds, 9 decimal precision)
        double median_iat;                // Median inter-arrival time (seconds, 9 decimal precision)
        double first_quartile_iat;        // First quartile of inter-arrival times (seconds, 9 decimal precision)
        double third_quartile_iat;        // Third quartile of inter-arrival times (seconds, 9 decimal precision)
        
        // Higher-order statistics for inter-arrival times
        double iat_skewness;              // Skewness of inter-arrival times
        double iat_kurtosis;              // Kurtosis of inter-arrival times
        
        // FFT analysis features for inter-arrival times
        std::vector<double> iat_fft_top_ten_features;  // Top 10 FFT frequency features (arctan of frequencies ranked by magnitude)
        bool fft_computed;                // Whether FFT analysis has been computed
        
        // Internal tracking field
        double last_timestamp;            // Timestamp of the last packet (seconds, 9 decimal precision)
        
        PacketIatStats() : iat_count(0), min_iat(0.0), max_iat(0.0), avg_iat(0.0),
                          median_iat(0.0), first_quartile_iat(0.0), third_quartile_iat(0.0),
                          iat_skewness(0.0), iat_kurtosis(0.0), fft_computed(false), last_timestamp(0.0) {}
    };
    
    // Control field statistics for statistical analysis
    struct ControlFieldStats {
        std::vector<uint32_t> control_field_sizes;  // Store control field sizes for statistical analysis
        uint64_t total_control_bytes;               // Total control field bytes
        uint32_t packet_count;                      // Packet count
        uint32_t min_control_size;                  // Minimum control field size
        uint32_t max_control_size;                  // Maximum control field size
        double avg_control_size;                    // Average control field size
        double median_control_size;                 // Median control field size
        double first_quartile;                      // First quartile (Q1) - 25th percentile
        double third_quartile;                      // Third quartile (Q3) - 75th percentile
        
        // Higher-order statistics for control field sizes
        double control_skewness;                    // Skewness of control field sizes
        double control_kurtosis;                    // Kurtosis of control field sizes
        
        ControlFieldStats() : total_control_bytes(0), packet_count(0), min_control_size(0), max_control_size(0), 
                             avg_control_size(0.0), median_control_size(0.0), first_quartile(0.0), third_quartile(0.0),
                             control_skewness(0.0), control_kurtosis(0.0) {}
    };

    // Connection statistics
    struct ConnectionStats {
        std::string uid;              // Unique connection ID
        std::string upstream_h;       // Source IP
        uint16_t upstream_p;         // Source port
        std::string downstream_h;     // Destination IP
        uint16_t downstream_p;       // Destination port
        std::string proto;           // Protocol
        std::string service;         // Service type
        double duration;             // Connection duration
        uint64_t upstream_bytes;    // Source bytes
        uint64_t downstream_bytes;  // Response bytes
        ConnectionState conn_state;  // Connection state
        uint64_t missed_bytes;      // Missed bytes
        ConnectionHistory history;   // Connection history
        uint32_t upstream_pkts;     // Source packet count
        uint64_t upstream_ip_bytes; // Source IP bytes
        uint32_t downstream_pkts;   // Response packet count
        uint64_t downstream_ip_bytes; // Response IP bytes
        uint8_t ip_proto;           // IP protocol number
        
        // Packet size statistics for upstream and downstream
        PacketSizeStats upstream_stats;    // Upstream packet size statistics
        PacketSizeStats downstream_stats;  // Downstream packet size statistics
        
        // Packet inter-arrival time statistics for upstream and downstream
        PacketIatStats upstream_iat_stats;    // Upstream packet inter-arrival time statistics
        PacketIatStats downstream_iat_stats;  // Downstream packet inter-arrival time statistics
        
        // Overall flow FFT analysis (combining all packets in chronological order)
        std::vector<double> flow_iat_fft_top_ten_features;  // Top 10 FFT frequency features for entire flow
        
    // Control field statistics for upstream and downstream
    ControlFieldStats upstream_control_stats;    // Upstream control field statistics
    ControlFieldStats downstream_control_stats;  // Downstream control field statistics

    // RTT statistics for upstream and downstream
    RTTStats upstream_rtt_stats;    // Upstream RTT statistics (client->server)
    RTTStats downstream_rtt_stats;  // Downstream RTT statistics (server->client)

    // Timestamps
    double start_time;           // Connection start time
    double last_seen;           // Last seen time

    // TCP specific features (upstream: client->server, downstream: server->client)
    // ACK packets
    uint32_t up_ack_pkts;       // Total number of ACK packets (client->server)
    uint32_t down_ack_pkts;     // Total number of ACK packets (server->client)
    
    // Pure ACK packets (ACK without data payload and without SYN/FIN/RST flags)
    uint32_t up_pure_acks;      // Pure ACK packets (client->server)
    uint32_t down_pure_acks;    // Pure ACK packets (server->client)
    
    // SACK packets
    uint32_t up_sack_pkts;      // SACK packets (client->server)
    uint32_t down_sack_pkts;    // SACK packets (server->client)
    
    // D-SACK packets
    uint32_t up_dsack_pkts;     // D-SACK packets (client->server)
    uint32_t down_dsack_pkts;   // D-SACK packets (server->client)
    
    // Maximum SACK blocks per ACK
    uint32_t up_max_sack_blks;  // Max SACK blocks per ACK (client->server)
    uint32_t down_max_sack_blks; // Max SACK blocks per ACK (server->client)
    
    // Unique bytes sent (excluding retransmissions and window probes)
    uint64_t up_unique_bytes;   // Unique bytes sent (client->server)
    uint64_t down_unique_bytes; // Unique bytes sent (server->client)
    
    // Actual data packets (packets with TCP data payload)
    uint32_t up_actual_data_pkts;  // Data packets (client->server)
    uint32_t down_actual_data_pkts; // Data packets (server->client)
    
    // Actual data bytes (including retransmissions)
    uint64_t up_actual_data_bytes;  // Data bytes (client->server)
    uint64_t down_actual_data_bytes; // Data bytes (server->client)
    
    // Retransmission statistics
    uint32_t up_rexmt_data_pkts;   // Retransmitted packets (client->server)
    uint32_t down_rexmt_data_pkts; // Retransmitted packets (server->client)
    uint64_t up_rexmt_data_bytes;  // Retransmitted bytes (client->server)
    uint64_t down_rexmt_data_bytes; // Retransmitted bytes (server->client)
    
    // Zero window probe statistics
    uint32_t up_zwnd_probe_pkts;   // Zero window probe packets (client->server)
    uint32_t down_zwnd_probe_pkts; // Zero window probe packets (server->client)
    uint64_t up_zwnd_probe_bytes;  // Zero window probe bytes (client->server)
    uint64_t down_zwnd_probe_bytes; // Zero window probe bytes (server->client)

    // PUSH bit statistics
    uint32_t up_pushed_data_pkts;  // Packets with PUSH bit set (client->server)
    uint32_t down_pushed_data_pkts; // Packets with PUSH bit set (server->client)
    
    // SYN bit statistics
    uint32_t up_syn_pkts;          // Packets with SYN bit set (client->server)
    uint32_t down_syn_pkts;        // Packets with SYN bit set (server->client)
    
    // FIN bit statistics
    uint32_t up_fin_pkts;          // Packets with FIN bit set (client->server)
    uint32_t down_fin_pkts;        // Packets with FIN bit set (server->client)

    // Out-of-order packet statistics
    uint32_t up_out_of_order_pkts;   // Out-of-order packets (client->server)
    uint32_t down_out_of_order_pkts; // Out-of-order packets (server->client)

    // Sequence number tracking for retransmission detection
    uint32_t up_last_seq;        // Last sequence number seen (client->server)
    uint32_t down_last_seq;      // Last sequence number seen (server->client)
    uint32_t up_last_ack;        // Last ACK number seen (client->server)
    uint32_t down_last_ack;      // Last ACK number seen (server->client)
    uint32_t up_expected_seq;    // Expected next sequence number (client->server)
    uint32_t down_expected_seq;  // Expected next sequence number (server->client)
    bool up_seq_initialized;     // Whether upstream sequence tracking is initialized
    bool down_seq_initialized;   // Whether downstream sequence tracking is initialized
    
    // RTT tracking structures
    std::map<uint32_t, RTTTrackingInfo> up_rtt_tracking;    // Upstream RTT tracking (client->server)
    std::map<uint32_t, RTTTrackingInfo> down_rtt_tracking;  // Downstream RTT tracking (server->client)
    
    // TCP specific fields
    bool syn_seen;              // Whether SYN was seen
    bool syn_ack_seen;          // Whether SYN-ACK was seen
    bool fin_seen;              // Whether FIN was seen
    bool rst_seen;              // Whether RST was seen
    bool ack_seen;              // Whether ACK was seen
    bool data_seen;             // Whether data was seen
    
    // Flow features for traffic analysis
    double time_since_last_conn;    // Time since the last connection between these hosts
    uint32_t bulk_trans_transitions; // Number of transitions between transaction and bulk transfer mode
    double time_spent_in_bulk;      // Amount of time spent in bulk transfer mode
    
    // Bulk mode tracking variables
    bool is_in_bulk_mode;           // Current state: whether connection is in bulk transfer mode
    double bulk_mode_start_time;    // Timestamp when bulk mode started
    uint32_t consecutive_same_dir_packets; // Count of consecutive packets in same direction
    bool last_packet_direction_up;  // Direction of last data packet (true = upstream, false = downstream)
    bool last_packet_had_data;      // Whether the last packet had data
    bool flow_fft_computed;          // Whether overall flow FFT has been computed
    
    // Constructor
    ConnectionStats() : 
        uid(""), upstream_h(""), upstream_p(0), downstream_h(""), downstream_p(0), proto(""),
        service(""), duration(0.0), upstream_bytes(0), downstream_bytes(0),
        conn_state(ConnectionState::OTH), missed_bytes(0),
        upstream_pkts(0), upstream_ip_bytes(0), downstream_pkts(0), downstream_ip_bytes(0),
        ip_proto(0), start_time(0.0), last_seen(0.0),
        up_ack_pkts(0), down_ack_pkts(0), up_pure_acks(0), down_pure_acks(0),
        up_sack_pkts(0), down_sack_pkts(0), up_dsack_pkts(0), down_dsack_pkts(0),
        up_max_sack_blks(0), down_max_sack_blks(0), up_unique_bytes(0), down_unique_bytes(0),
        up_actual_data_pkts(0), down_actual_data_pkts(0), up_actual_data_bytes(0), down_actual_data_bytes(0),
        up_rexmt_data_pkts(0), down_rexmt_data_pkts(0), up_rexmt_data_bytes(0), down_rexmt_data_bytes(0),
        up_zwnd_probe_pkts(0), down_zwnd_probe_pkts(0), up_zwnd_probe_bytes(0), down_zwnd_probe_bytes(0),
        up_pushed_data_pkts(0), down_pushed_data_pkts(0),
        up_syn_pkts(0), down_syn_pkts(0),
        up_fin_pkts(0), down_fin_pkts(0),
        up_out_of_order_pkts(0), down_out_of_order_pkts(0),
        up_last_seq(0), down_last_seq(0), up_last_ack(0), down_last_ack(0),
        up_expected_seq(0), down_expected_seq(0), up_seq_initialized(false), down_seq_initialized(false),
        syn_seen(false), syn_ack_seen(false), fin_seen(false),
        rst_seen(false), ack_seen(false), data_seen(false),
        time_since_last_conn(0.0), bulk_trans_transitions(0), time_spent_in_bulk(0.0),
        is_in_bulk_mode(false), bulk_mode_start_time(0.0), consecutive_same_dir_packets(0),
        last_packet_direction_up(false), last_packet_had_data(false), flow_fft_computed(false) {}
};

class ConnectionTracker {
public:
    ConnectionTracker();
    ~ConnectionTracker();
    
    // Process packet and update connection statistics
    void processPacket(const PacketMetadata& meta);
    
    // Get connection statistics
    std::vector<ConnectionStats> getAllConnections() const;
    std::vector<ConnectionStats> getCompletedConnections() const;
    
    // Clean up timeout connections
    void cleanupTimeoutConnections(double timeout_seconds = 3600.0);
    
    // Set UDP flow timeout (default 30 seconds)
    void setUDPFlowTimeout(double timeout_seconds);
    
    // Check if a connection is completed and get completed connections
    bool isConnectionCompleted(const ConnectionStats& conn) const;
    std::vector<ConnectionStats> getAndRemoveCompletedConnections();
    
    // Generate unique connection ID
    std::string generateConnectionUID(const std::string& src_ip, uint16_t src_port,
                                    const std::string& dst_ip, uint16_t dst_port,
                                    const std::string& protocol);
    
    // Convert connection state to string
    static std::string connectionStateToString(ConnectionState state);
    
    // Service type detection
    static std::string detectService(const std::string& protocol, uint16_t port);

private:
    mutable std::mutex connections_mutex_;
    std::unordered_map<std::string, ConnectionStats> connections_;
    
    // Host pair tracking for time since last connection feature
    mutable std::mutex host_pairs_mutex_;
    std::unordered_map<std::string, double> host_pair_last_seen_;
    
    // Queue for completed connections
    mutable std::mutex completed_connections_mutex_;
    std::vector<ConnectionStats> completed_connections_;
    
    // Generate connection key
    std::string generateConnectionKey(const std::string& src_ip, uint16_t src_port,
                                     const std::string& dst_ip, uint16_t dst_port,
                                     const std::string& protocol);
    
    // Update connection state
    void updateConnectionState(ConnectionStats& conn, const PacketMetadata& meta);
    
    // Update connection history
    void updateConnectionHistory(ConnectionStats& conn, const PacketMetadata& meta);
    
    // Detect TCP connection state
    ConnectionState detectTCPState(const ConnectionStats& conn);
    
    // Detect UDP connection state
    ConnectionState detectUDPState(const ConnectionStats& conn);
    
    // Detect ICMP connection state
    ConnectionState detectICMPState(const ConnectionStats& conn);
    
    // Generate history string
    std::string generateHistoryString(const ConnectionHistory& history);
    
    // Calculate packet size statistics
    void calculatePacketSizeStats(PacketSizeStats& stats) const;
    
    // Calculate packet inter-arrival time statistics
    void calculatePacketIatStats(PacketIatStats& stats) const;
    
    // Calculate control field statistics
    void calculateControlFieldStats(ControlFieldStats& stats) const;
    
    // Calculate RTT statistics
    void calculateRTTStats(RTTStats& stats) const;
    
    // Calculate packet size statistics (internal)
    void calculateSizeStatistics(PacketSizeStats& stats) const;
    
    // Calculate inter-arrival time statistics (internal)
    void calculateIatStatistics(PacketIatStats& stats) const;
    
    // Calculate control field statistics (internal)
    void calculateControlFieldStatistics(ControlFieldStats& stats) const;
    
    // FFT analysis methods
    void calculateFFTFeatures(PacketIatStats& stats) const;
    void calculateOverallFlowFFT(ConnectionStats& conn);
    
    // Flow feature calculation methods
    std::string generateHostPairKey(const std::string& ip1, const std::string& ip2);
    void updateTimeSinceLastConnection(ConnectionStats& conn, const PacketMetadata& metadata);
    void updateBulkModeTracking(ConnectionStats& conn, const PacketMetadata& metadata);
    void finalizeBulkModeTracking(ConnectionStats& conn);
    
    // Calculate skewness and kurtosis (internal)
    void calculateSkewnessAndKurtosis(const std::vector<double>& data, double mean, 
                                     double& skewness, double& kurtosis) const;
    
    // Update packet size statistics
    void updatePacketSizeStats(PacketSizeStats& stats, uint32_t packet_size);
    
    // Update packet inter-arrival time statistics
    void updatePacketIatStats(PacketIatStats& stats, double timestamp_seconds);
    
    // Update control field statistics
    void updateControlFieldStats(ControlFieldStats& stats, uint32_t control_field_size);
    
    // TCP feature extraction methods
    void updateTCPFeatures(ConnectionStats& conn, const PacketMetadata& metadata);
    bool isPureACK(const PacketMetadata& metadata) const;
    bool hasSACK(const PacketMetadata& metadata) const;
    bool hasDSACK(const PacketMetadata& metadata) const;
    uint32_t getSACKBlockCount(const PacketMetadata& metadata) const;
    bool isRetransmission(ConnectionStats& conn, const PacketMetadata& metadata) const;
    bool isZeroWindowProbe(ConnectionStats& conn, const PacketMetadata& metadata) const;
    void updateSequenceTracking(ConnectionStats& conn, const PacketMetadata& metadata);
    
    // RTT tracking and calculation methods
    void updateRTTTracking(ConnectionStats& conn, const PacketMetadata& metadata);
    void processRTTACK(ConnectionStats& conn, const PacketMetadata& metadata);
    bool isValidRTTSample(const RTTTrackingInfo& tracking_info, const PacketMetadata& metadata) const;
    void addRTTSample(RTTStats& stats, double rtt_value);
    void calculateRTTStatistics(RTTStats& stats) const;
    
    // UDP timeout management methods
    void updateUDPTimeout(const std::string& connection_key, double current_time);
    void removeUDPTimeout(const std::string& connection_key);
    void flushExpiredUDPFlows(double current_time);
    
    // Counter
    uint64_t connection_counter_;
    
    // UDP flow timeout configuration
    double udp_flow_timeout_;
    
    // UDP flow timeout management using red-black tree (std::map)
    struct UDPTimeoutKey {
        uint64_t timeout_nanoseconds;   // Timeout time in nanoseconds
        uint64_t sequence_id;           // Sequence ID to ensure uniqueness
        
        // Default constructor for std::map compatibility
        UDPTimeoutKey() : timeout_nanoseconds(0), sequence_id(0) {}
        
        UDPTimeoutKey(uint64_t timeout_ns, uint64_t seq_id) 
            : timeout_nanoseconds(timeout_ns), sequence_id(seq_id) {}
        
        // Comparison operator for std::map ordering
        bool operator<(const UDPTimeoutKey& other) const {
            if (timeout_nanoseconds != other.timeout_nanoseconds) {
                return timeout_nanoseconds < other.timeout_nanoseconds;
            }
            return sequence_id < other.sequence_id;
        }
    };
    
    // Map: timeout_key -> connection_key (ordered by timeout time)
    std::map<UDPTimeoutKey, std::string> udp_timeout_tree_;
    // Reverse mapping: connection_key -> timeout_key (for O(log n) removal)
    std::map<std::string, UDPTimeoutKey> udp_connection_to_timeout_;
    mutable std::mutex udp_timeout_mutex_;
    uint64_t timeout_sequence_counter_;  // Counter for unique sequence IDs
    
    // FFT analyzer for packet inter-arrival time analysis
    mutable FFTAnalyzer fft_analyzer_;
};

#endif // CONNECTION_TRACKER_H
