#ifndef PACKET_METADATA_H
#define PACKET_METADATA_H

#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>

// Forward declare parser classes to avoid circular dependencies
class DHCPParser;

// Data Link Layer (Ethernet) metadata
struct EthernetMetadata {
    uint8_t src_mac[6] = {0};
    uint8_t dst_mac[6] = {0};
    uint16_t ethertype = 0;
};

// VLAN metadata
struct VLANMetadata {
    uint16_t vlan_id = 0;
    uint8_t vlan_priority = 0;
    bool dei_flag = false;         // Drop Eligible Indicator (DEI)
    uint16_t inner_ethertype = 0;
};

// GRE metadata
struct GREMetadata {
    uint16_t protocol = 0;
    uint8_t version = 0;           // GRE version (0 or 1)
    uint8_t recursion_control = 0; // Recursion control field
    bool checksum_bit = false;     // Checksum bit flag
    bool routing_bit = false;      // Routing bit flag
    bool key_bit = false;          // Key bit flag
    bool sequence_bit = false;     // Sequence number bit flag
    bool strict_source_route = false; // Strict source route bit flag
    bool ack_sequence_bit = false; // Acknowledgment sequence bit flag (GREv1 only)
    
    // Optional fields
    uint16_t checksum = 0;         // Checksum value if present
    uint16_t offset = 0;           // Offset value if present
    uint32_t key = 0;              // Key value if present
    uint32_t sequence = 0;         // Sequence number if present
    uint32_t ack_sequence = 0;     // Acknowledgment sequence if present (GREv1 only)
    
    // GREv1 specific fields
    uint16_t payload_length = 0;   // Payload length (GREv1 only)
    uint16_t call_id = 0;          // Call ID (GREv1 only)
};

// MPLS metadata
struct MPLSMetadata {
    struct Label {
        uint32_t label = 0;           // MPLS label value (20 bits)
        uint8_t tc = 0;               // Traffic class/EXP (3 bits)
        bool bos = false;             // Bottom of stack flag (1 bit)
        uint8_t ttl = 0;              // Time to live (8 bits)
    };
    
    std::vector<Label> label_stack;   // MPLS label stack
    uint8_t stack_depth = 0;          // Label stack depth
    uint16_t ethertype = 0;           // Original ethertype (0x8847/0x8848)
    uint16_t payload_protocol = 0;    // Payload protocol type
    bool unicast = true;              // Whether unicast (true=0x8847, false=0x8848)
};

// VXLAN metadata
struct VXLANMetadata {
    uint8_t flags = 0;             // VXLAN flags (I bit, etc.)
    uint8_t reserved1 = 0;         // Reserved field 1
    uint16_t reserved2 = 0;        // Reserved field 2
    uint32_t vni = 0;              // 24-bit Virtual Network Identifier
    uint8_t reserved3 = 0;         // Reserved field 3
    bool i_bit = false;            // I bit flag (VNI valid)
    bool r_bit = false;            // R bit flag (reserved)
    bool r_bit2 = false;           // R bit flag 2 (reserved)
    bool r_bit3 = false;           // R bit flag 3 (reserved)
    bool r_bit4 = false;           // R bit flag 4 (reserved)
    bool r_bit5 = false;           // R bit flag 5 (reserved)
    bool r_bit6 = false;           // R bit flag 6 (reserved)
    bool r_bit7 = false;           // R bit flag 7 (reserved)
};

// WiFi metadata
struct WiFiMetadata {
    uint8_t src_mac[6] = {0};      // Source MAC address
    uint8_t dst_mac[6] = {0};      // Destination MAC address
    uint8_t bssid[6] = {0};        // BSSID (Basic Service Set Identifier)
    uint8_t transmitter_mac[6] = {0}; // Transmitter MAC address
    uint8_t receiver_mac[6] = {0};    // Receiver MAC address
    
    uint16_t frame_control = 0;    // Frame Control field
    uint16_t duration = 0;         // Duration/ID field
    uint16_t sequence_number = 0;  // Sequence Number field
    
    // Frame Control subfields
    uint8_t protocol_version = 0;  // Protocol Version (2 bits)
    uint8_t frame_type = 0;        // Frame Type (2 bits)
    uint8_t frame_subtype = 0;     // Frame Subtype (4 bits)
    bool to_ds = false;            // To DS flag
    bool from_ds = false;          // From DS flag
    bool more_frag = false;        // More Fragments flag
    bool retry = false;            // Retry flag
    bool power_mgmt = false;       // Power Management flag
    bool more_data = false;        // More Data flag
    bool wep = false;              // WEP flag
    bool order = false;            // Order flag
    
    // Management frame specific fields
    uint64_t timestamp = 0;        // Timestamp
    uint16_t beacon_interval = 0;  // Beacon Interval
    uint16_t capability_info = 0;  // Capability Information
    
    // Data frame specific fields
    uint8_t qos_control = 0;      // QoS Control field
    
    // Radio information (if available)
    int8_t rssi = 0;              // Received Signal Strength Indicator
    uint8_t channel = 0;          // Channel number
    uint8_t data_rate = 0;        // Data rate in Mbps
};

// IPv4 metadata
struct IPv4Metadata {
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol = 0;
    uint8_t ttl = 0;
    uint8_t tos = 0;
    uint16_t id = 0;
    uint16_t fragment_offset = 0;
    bool df_bit = false;
    bool mf_bit = false;
};

// VRRP metadata
struct VRRPMetadata {
    uint8_t version = 0;              // VRRP version (2 or 3)
    uint8_t type = 0;                 // VRRP packet type (1=Advertisement)
    uint8_t virtual_router_id = 0;    // Virtual Router ID (1-255)
    uint8_t priority = 0;             // Router priority (0-255, 255=master)
    uint8_t count_ip = 0;             // Number of IP addresses
    uint8_t auth_type = 0;            // Authentication type (0=None, 1=Simple, 2=MD5)
    uint8_t adver_int = 0;            // Advertisement interval (seconds)
    uint16_t checksum = 0;            // VRRP checksum
    bool checksum_valid = false;       // Whether checksum validation passed
    
    // VRRP v2 specific fields
    std::vector<uint32_t> virtual_ips; // Virtual IP addresses
    
    // VRRP v3 specific fields
    uint16_t max_adver_int = 0;       // Maximum advertisement interval (centiseconds)
    uint16_t reserved = 0;            // Reserved field
    
    // Authentication data (if present)
    std::string auth_data;            // Authentication data
    
    // Helper methods
    std::string getVirtualIPString(size_t index = 0) const;
    std::string getPriorityString() const;
    std::string getTypeString() const;
    std::string getVersionString() const;
    std::string getAuthTypeString() const;
};

// HTTP metadata
struct HTTPMetadata {
    // Basic HTTP information
    std::string method;               // HTTP method (GET, POST, PUT, etc.)
    std::string uri;                  // Request URI
    std::string version;              // HTTP version (HTTP/1.0, HTTP/1.1, HTTP/2.0)
    uint16_t status_code = 0;         // HTTP status code (for responses)
    std::string status_text;          // HTTP status text (for responses)
    
    // Message type
    bool is_request = false;          // True if this is an HTTP request
    bool is_response = false;         // True if this is an HTTP response
    std::string type;                 // HTTP type: "REQUEST" or "RESPONSE"
    
    // Headers
    std::map<std::string, std::string> headers; // HTTP headers
    
    // Common header fields (for easy access)
    std::string host;                 // Host header
    std::string user_agent;           // User-Agent header
    std::string content_type;         // Content-Type header
    std::string content_length;       // Content-Length header
    std::string connection;           // Connection header
    std::string accept;               // Accept header
    std::string accept_encoding;      // Accept-Encoding header
    std::string accept_language;      // Accept-Language header
    std::string cache_control;        // Cache-Control header
    std::string cookie;               // Cookie header
    std::string set_cookie;           // Set-Cookie header
    std::string referer;              // Referer header
    std::string location;             // Location header (for redirects)
    std::string server;               // Server header
    std::string date;                 // Date header
    std::string last_modified;        // Last-Modified header
    std::string etag;                 // ETag header
    std::string expires;              // Expires header
    
    // Body information
    size_t body_length = 0;           // Length of HTTP body
    std::string body_preview;         // Preview of HTTP body (first 100 chars)
    
    // Helper methods
    std::string getMethodString() const;
    std::string getStatusCodeString() const;
    std::string getVersionString() const;
    std::string getHeaderValue(const std::string& name) const;
    bool hasHeader(const std::string& name) const;
};

// IPv6 metadata
struct IPv6Metadata {
    std::string src_ip;
    std::string dst_ip;
    uint8_t next_header = 0;
    uint8_t hop_limit = 0;
    uint32_t flow_label = 0;
    uint8_t traffic_class = 0;
    uint16_t payload_length = 0;
    
    // Extension headers support
    struct ExtensionHeader {
        uint8_t type = 0;           // Extension header type
        uint8_t length = 0;         // Length in 8-octet units (excluding first 8 octets)
        std::string description;    // Human-readable description
        bool present = false;       // Whether this extension header is present
    };
    
    ExtensionHeader hop_by_hop;     // Hop-by-Hop Options (0)
    ExtensionHeader routing;        // Routing (43)
    ExtensionHeader fragment;       // Fragment (44)
    ExtensionHeader destination;    // Destination Options (60)
    ExtensionHeader ah;            // Authentication Header (51)
    ExtensionHeader esp;           // Encapsulating Security Payload (50)
    
    // Fragment-specific fields
    uint16_t fragment_offset = 0;   // Fragment offset (13 bits)
    bool fragment_more = false;     // More fragments flag
    uint32_t fragment_id = 0;       // Fragment identification
    
    // Routing-specific fields
    uint8_t routing_type = 0;       // Routing type
    uint8_t segments_left = 0;      // Segments left
};

// TCP metadata
struct TCPMetadata {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint16_t flags = 0;
    uint16_t window = 0;
    uint16_t urgent_pointer = 0;
    bool syn = false;
    bool ack_flag = false;
    bool fin = false;
    bool rst = false;
    bool psh = false;
    bool urg = false;
};

// UDP metadata
struct UDPMetadata {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t length = 0;
    uint16_t checksum = 0;
};

// ARP metadata
struct ARPMetadata {
    uint16_t hardware_type = 0;      // Hardware type (1 for Ethernet)
    uint16_t protocol_type = 0;      // Protocol type (0x0800 for IPv4)
    uint8_t hardware_size = 0;       // Hardware address size (6 for MAC)
    uint8_t protocol_size = 0;       // Protocol address size (4 for IPv4)
    uint16_t operation = 0;          // Operation (1=request, 2=reply)
    
    uint8_t sender_mac[6] = {0};     // Sender hardware address
    uint8_t sender_ip[4] = {0};      // Sender protocol address
    uint8_t target_mac[6] = {0};     // Target hardware address
    uint8_t target_ip[4] = {0};      // Target protocol address
    
    std::string sender_mac_str;      // Sender MAC as string
    std::string sender_ip_str;       // Sender IP as string
    std::string target_mac_str;      // Target MAC as string
    std::string target_ip_str;       // Target IP as string
};

// ICMP metadata
struct ICMPMetadata {
    uint8_t type = 0;                // ICMP message type
    uint8_t code = 0;                // ICMP message code
    uint16_t checksum = 0;           // ICMP checksum
    uint16_t identifier = 0;         // Identifier (for echo request/reply)
    uint16_t sequence = 0;           // Sequence number (for echo request/reply)
    
    // For destination unreachable messages
    uint32_t original_ip = 0;        // Original IP address from unreachable packet
    uint8_t original_protocol = 0;   // Original protocol from unreachable packet
    uint16_t original_port = 0;      // Original port from unreachable packet (if applicable)
    
    // For redirect messages
    uint32_t gateway_ip = 0;         // Gateway IP address for redirect
    
    // For time exceeded messages
    uint8_t unused = 0;              // Unused field in time exceeded
    
    // For parameter problem messages
    uint8_t pointer = 0;             // Pointer to problematic octet
    
    // ICMP message type descriptions
    std::string type_description;    // Human-readable type description
    std::string code_description;    // Human-readable code description
    
    // Checksum validation
    bool checksum_valid = false;     // Whether the checksum is valid
};

// IGMP metadata
struct IGMPMetadata {
    uint8_t type = 0;                // IGMP message type
    uint8_t max_response_time = 0;   // Maximum Response Time (for query messages)
    uint16_t checksum = 0;           // IGMP checksum
    uint32_t group_address = 0;      // Group Address (IPv4 multicast address)
    
    // Version-specific fields
    uint8_t version = 0;             // IGMP version (1, 2, or 3)
    
    // IGMPv3 specific fields
    uint8_t qrv = 0;                 // Querier's Robustness Variable (IGMPv3)
    uint8_t qqic = 0;                // Querier's Query Interval Code (IGMPv3)
    uint16_t num_sources = 0;        // Number of Sources (IGMPv3)
    std::vector<uint32_t> source_addresses; // Source Address List (IGMPv3)
    
    // IGMPv2 specific fields
    uint8_t reserved = 0;            // Reserved field (IGMPv2)
    
    // Message type descriptions
    std::string type_description;    // Human-readable type description
    
    // Checksum validation
    bool checksum_valid = false;     // Whether the checksum is valid
    
    // Helper functions
    std::string getGroupAddressString() const;
    std::string getSourceAddressString(uint32_t addr) const;
};

// ICMPv6 metadata
struct ICMPv6Metadata {
    uint8_t type = 0;                // ICMPv6 message type
    uint8_t code = 0;                // ICMPv6 message code
    uint16_t checksum = 0;           // ICMPv6 checksum
    uint16_t identifier = 0;         // Identifier (for echo request/reply)
    uint16_t sequence = 0;           // Sequence number (for echo request/reply)
    
    // For destination unreachable messages
    uint32_t original_ipv6[4] = {0}; // Original IPv6 address from unreachable packet (128 bits)
    uint8_t original_protocol = 0;   // Original protocol from unreachable packet
    uint16_t original_port = 0;      // Original port from unreachable packet (if applicable)
    
    // For packet too big messages
    uint32_t mtu = 0;                // MTU value for packet too big messages
    
    // For time exceeded messages
    uint8_t unused = 0;              // Unused field in time exceeded
    
    // For parameter problem messages
    uint8_t pointer = 0;             // Pointer to problematic octet
    
    // For neighbor discovery messages
    uint32_t target_address[4] = {0}; // Target address for neighbor discovery
    uint32_t source_link_layer[2] = {0}; // Source link-layer address option
    uint32_t target_link_layer[2] = {0}; // Target link-layer address option
    
    // For router discovery messages
    uint8_t router_lifetime = 0;     // Router lifetime
    uint32_t reachable_time = 0;     // Reachable time
    uint32_t retrans_timer = 0;     // Retransmission timer
    
    // ICMPv6 message type descriptions
    std::string type_description;    // Human-readable type description
    std::string code_description;    // Human-readable code desciption
    
    // Checksum validation
    bool checksum_valid = false;     // Whether the checksum is valid
    
    // IPv6 address conversion helpers
    std::string getOriginalIPv6String() const;
    std::string getTargetAddressString() const;
    std::string getSourceLinkLayerString() const;
    std::string getTargetLinkLayerString() const;
};

// FTP metadata
struct FTPMetadata {
    // Basic FTP information
    bool is_control = false;          // True if control connection (port 21)
    bool is_data = false;             // True if data connection (port 20)
    std::string type;                 // "CONTROL" or "DATA"
    
    // Control connection fields (port 21)
    std::string command;              // FTP command (USER, PASS, RETR, STOR, LIST, etc.)
    std::string arguments;            // Command arguments
    uint16_t response_code = 0;       // Server response code (200, 220, 230, etc.)
    std::string response_text;        // Response text/description
    bool is_request = false;          // True if client command
    bool is_response = false;         // True if server response
    
    // Data connection fields (port 20)
    size_t data_length = 0;           // Length of data payload
    std::string data_preview;         // Preview of data content (first 100 bytes)
    std::string transfer_mode;        // ASCII, Binary, etc.
    
    // Helper methods
    std::string getCommandString() const;
    std::string getResponseString() const;
    std::string getTypeString() const;
    bool isValidCommand(const std::string& cmd) const;
    bool isValidResponseCode(uint16_t code) const;
};

// SMTP metadata
struct SMTPMetadata {
    // Basic SMTP information
    bool is_request = false;          // True if client command
    bool is_response = false;         // True if server response
    std::string type;                 // "REQUEST" or "RESPONSE"
    
    // Request fields (client to server)
    std::string command;              // SMTP command (HELO, EHLO, MAIL, RCPT, DATA, etc.)
    std::string arguments;            // Command arguments
    
    // Response fields (server to client)
    uint16_t status_code = 0;         // Server response code (220, 250, 354, 550, etc.)
    std::string status_text;          // Response text/description
    
    // Common fields
    size_t message_length = 0;        // Length of SMTP message
    std::string message_preview;      // Preview of message content (first 100 chars)
    
    // Helper methods
    std::string getCommandString() const;
    std::string getStatusString() const;
    std::string getTypeString() const;
    bool isValidCommand(const std::string& cmd) const;
    bool isValidStatusCode(uint16_t code) const;
    std::string getCommandDescription(const std::string& cmd) const;
    std::string getStatusCodeDescription(uint16_t code) const;
};

// DHCP metadata
struct DHCPMetadata {
    // Basic DHCP information
    uint8_t op = 0;                   // Message type (1=Request, 2=Reply)
    uint8_t htype = 0;                // Hardware type (1=Ethernet)
    uint8_t hlen = 0;                 // Hardware address length (6 for Ethernet)
    uint8_t hops = 0;                 // Number of relay agent hops
    uint32_t xid = 0;                 // Transaction ID
    uint16_t secs = 0;                // Seconds elapsed since client started trying to boot
    uint16_t flags = 0;               // Flags field
    
    // IP addresses
    std::string ciaddr;               // Client IP address
    std::string yiaddr;               // Your (client) IP address
    std::string siaddr;               // Next server IP address
    std::string giaddr;               // Relay agent IP address
    
    // Hardware address
    std::string chaddr;               // Client hardware address (MAC)
    
    // Server and file names
    std::string sname;                // Optional server host name
    std::string file;                 // Boot file name
    
    // DHCP Options
    uint8_t message_type = 0;         // DHCP Message Type (53)
    uint32_t lease_time = 0;          // IP Address Lease Time (51)
    std::string subnet_mask;          // Subnet Mask (1)
    std::string router;               // Router/Gateway (3)
    std::string dns_servers;          // Domain Name Servers (6)
    std::string domain_name;          // Domain Name (15)
    std::string dhcp_server_id;       // DHCP Server Identifier (54)
    
    // Flags breakdown
    bool broadcast_flag = false;      // Broadcast flag from flags field
    
    // Message type string
    std::string message_type_str;     // Human-readable message type
    std::string op_str;               // Human-readable op code
    
    // Helper methods
    std::string getMessageTypeString() const;
    std::string getOpString() const;
    std::string getFlagsString() const;
};

// DHCPv6 metadata
struct DHCPv6Metadata {
    // Basic DHCPv6 information
    uint8_t msg_type = 0;             // DHCPv6 message type
    uint32_t transaction_id = 0;      // Transaction ID (3 bytes)
    
    // DHCPv6 Options
    uint8_t message_type = 0;         // DHCPv6 Message Type (1)
    uint32_t preferred_lifetime = 0;  // Preferred Lifetime (7)
    uint32_t valid_lifetime = 0;      // Valid Lifetime (8)
    std::string server_id;            // Server Identifier (2)
    std::string client_id;            // Client Identifier (3)
    std::string ia_na;                // IA_NA (Identity Association for Non-temporary Addresses) (3)
    std::string ia_ta;                // IA_TA (Identity Association for Temporary Addresses) (4)
    std::string iaaddr;               // IA Address (5)
    std::string dns_servers;          // DNS Recursive Name Server (23)
    std::string domain_list;          // Domain Search List (24)
    std::string sip_servers;          // SIP Servers (21)
    std::string ntp_servers;          // NTP Servers (56)
    std::string rapid_commit;         // Rapid Commit (14)
    std::string user_class;           // User Class (15)
    std::string vendor_class;         // Vendor Class (16)
    std::string vendor_opts;          // Vendor-specific Information (17)
    std::string interface_id;         // Interface ID (18)
    std::string reconfigure_msg;      // Reconfigure Message (19)
    std::string reconfigure_accept;   // Reconfigure Accept (20)
    
    // Message type string
    std::string message_type_str;     // Human-readable message type
    
    // Helper methods
    std::string getMessageTypeString() const;
    std::string getTransactionIdString() const;
};

// DNS metadata
struct DNSMetadata {
    // DNS Header fields
    uint16_t transaction_id = 0;      // Transaction ID for request/response matching
    uint16_t flags = 0;               // DNS flags field
    uint16_t questions = 0;           // QDCOUNT - Number of questions
    uint16_t answers = 0;             // ANCOUNT - Number of answer records
    uint16_t authority_records = 0;   // NSCOUNT - Number of authority records
    uint16_t additional_records = 0;  // ARCOUNT - Number of additional records
    
    // DNS Flags breakdown
    bool qr = false;                  // Query/Response flag (0=Query, 1=Response)
    uint8_t opcode = 0;              // Operation code (4 bits)
    bool aa = false;                  // Authoritative Answer flag
    bool tc = false;                  // Truncation flag
    bool rd = false;                  // Recursion Desired flag
    bool ra = false;                  // Recursion Available flag
    uint8_t z = 0;                   // Reserved field (3 bits, must be 0)
    uint8_t rcode = 0;               // Response code (4 bits)
    
    // Message type
    std::string message_type;         // "QUERY" or "RESPONSE"
    
    // Question section (first question only for simplicity)
    std::string qname;                // Query domain name
    uint16_t qtype = 0;              // Query type (A=1, AAAA=28, MX=15, etc.)
    uint16_t qclass = 0;             // Query class (IN=1)
    std::string qtype_str;           // Human-readable query type
    std::string qclass_str;          // Human-readable query class
    
    // Answer section (simplified - stores first answer)
    struct DNSResourceRecord {
        std::string name;             // Resource record name
        uint16_t type = 0;           // Resource record type
        uint16_t rr_class = 0;       // Resource record class
        uint32_t ttl = 0;            // Time to live
        uint16_t rdlength = 0;       // Resource data length
        std::string rdata;           // Resource data (formatted based on type)
        std::string type_str;        // Human-readable type
    };
    
    std::vector<DNSResourceRecord> answer_records;     // Answer section records
    std::vector<DNSResourceRecord> authority_records_list; // Authority section records
    std::vector<DNSResourceRecord> additional_records_list; // Additional section records
    
    // Helper fields
    std::string opcode_str;          // Human-readable opcode
    std::string rcode_str;           // Human-readable response code
    bool is_query = false;           // Convenience flag for queries
    bool is_response = false;        // Convenience flag for responses
    
    // Statistics
    size_t total_records = 0;        // Total number of resource records
    size_t dns_packet_size = 0;      // Total DNS packet size
    
    // Helper methods
    std::string getOpcodeString() const;
    std::string getRcodeString() const;
    std::string getQtypeString() const;
    std::string getQclassString() const;
    std::string getTypeString(uint16_t type) const;
    std::string getFlagsString() const;
};

// NDP (Neighbor Discovery Protocol) metadata
struct NDPMetadata {
    uint8_t message_type = 0;            // NDP message type (133=RS, 134=RA, 135=NS, 136=NA, 137=Redirect)
    
    // Router Solicitation/Advertisement (RS/RA) fields
    uint8_t cur_hop_limit = 0;           // Current hop limit (RA only)
    uint8_t flags = 0;                   // Flags (M=managed address config, O=other config, H=home agent, Prf=router preference)
    uint16_t router_lifetime = 0;        // Router lifetime (RA only)
    uint32_t reachable_time = 0;         // Reachable time (RA only)
    uint32_t retrans_timer = 0;          // Retransmission timer (RA only)
    
    // Router Advertisement flags
    bool managed_addr_config = false;    // M flag: managed address configuration
    bool other_config = false;           // O flag: other configuration
    bool home_agent = false;             // H flag: home agent
    uint8_t router_preference = 0;       // Prf: router preference (0=medium, 1=high, 3=low)
    
    // Neighbor Solicitation/Advertisement (NS/NA) fields
    uint8_t target_address[16] = {0};    // Target IPv6 address (NS/NA)
    
    // Neighbor Advertisement flags
    bool router_flag = false;            // R flag: router flag
    bool solicited_flag = false;         // S flag: solicited flag
    bool override_flag = false;          // O flag: override flag
    
    // Redirect fields
    uint8_t redirect_target[16] = {0};   // Redirect target address (Redirect only)
    uint8_t redirect_destination[16] = {0}; // Redirect destination address (Redirect only)
    
    // NDP Options
    bool has_source_link_layer = false;  // Whether has source link-layer address option
    bool has_target_link_layer = false;  // Whether has target link-layer address option
    bool has_prefix_info = false;        // Whether has prefix information option
    bool has_redirected_header = false;  // Whether has redirected header option
    bool has_mtu = false;                // Whether has MTU option
    
    uint8_t source_link_layer[6] = {0};  // Source link-layer address (MAC address)
    uint8_t target_link_layer[6] = {0};  // Target link-layer address (MAC address)
    uint32_t mtu = 0;                    // MTU value
    
    // Prefix Information Option
    uint8_t prefix_length = 0;           // Prefix length
    bool on_link_flag = false;           // L flag: on-link flag
    bool autonomous_flag = false;        // A flag: autonomous configuration flag
    uint32_t valid_lifetime = 0;         // Valid lifetime
    uint32_t preferred_lifetime = 0;     // Preferred lifetime
    uint8_t prefix[16] = {0};            // Prefix address
    
    // DAD (Duplicate Address Detection) related
    bool is_dad_packet = false;          // Whether is DAD packet (source address is ::)
    bool is_solicited_node_multicast = false; // Whether destination is solicited-node multicast
    
    // Auxiliary information
    std::string message_description;     // Message type description
    std::string target_address_str;      // Target address string
    std::string source_link_layer_str;   // Source link-layer address string
    std::string target_link_layer_str;   // Target link-layer address string
    std::string prefix_str;              // Prefix address string
    std::string redirect_target_str;     // Redirect target string
    std::string redirect_destination_str; // Redirect destination string
    
    // Helper methods
    std::string getTargetAddressString() const;
    std::string getSourceLinkLayerString() const;
    std::string getTargetLinkLayerString() const;
    std::string getPrefixString() const;
    std::string getRedirectTargetString() const;
    std::string getRedirectDestinationString() const;
};

// NTP metadata
struct NTPMetadata {
    // NTP Header fields (48 bytes total)
    uint8_t li = 0;                    // Leap Indicator (2 bits)
    uint8_t vn = 0;                    // Version Number (3 bits)
    uint8_t mode = 0;                  // Mode (3 bits)
    uint8_t stratum = 0;               // Stratum (8 bits)
    uint8_t poll = 0;                  // Poll Interval (8 bits)
    int8_t precision = 0;              // Precision (8 bits, signed)
    uint32_t root_delay = 0;           // Root Delay (32 bits)
    uint32_t root_dispersion = 0;      // Root Dispersion (32 bits)
    uint32_t reference_id = 0;         // Reference Identifier (32 bits)
    uint64_t reference_timestamp = 0;  // Reference Timestamp (64 bits)
    uint64_t originate_timestamp = 0;  // Originate Timestamp (64 bits)
    uint64_t receive_timestamp = 0;    // Receive Timestamp (64 bits)
    uint64_t transmit_timestamp = 0;   // Transmit Timestamp (64 bits)
    
    // Human-readable strings
    std::string li_str;                // Leap Indicator description
    std::string vn_str;                // Version Number description
    std::string mode_str;              // Mode description
    std::string stratum_str;           // Stratum description
    std::string reference_id_str;      // Reference Identifier description
    
    // Calculated fields
    double time_offset = 0.0;          // Calculated time offset
    double round_trip_delay = 0.0;     // Calculated round trip delay
    
    // Helper methods
    std::string getLeapIndicatorString() const;
    std::string getVersionString() const;
    std::string getModeString() const;
    std::string getStratumString() const;
    std::string getReferenceIdString() const;
    std::string getTimestampString(uint64_t timestamp) const;
    void calculateTimeMetrics();
};

// SSH metadata
struct SSHMetadata {
    // Basic SSH information
    bool is_identification = false;    // True if this is SSH identification message
    bool is_handshake = false;        // True if this is SSH handshake message
    bool is_key_exchange = false;     // True if this is SSH key exchange init message
    bool is_encrypted = false;        // True if this is encrypted SSH message
    std::string message_type;         // "IDENTIFICATION", "HANDSHAKE", "KEY_EXCHANGE", "ENCRYPTED"
    
    // SSH identification message fields
    std::string identification_string; // SSH version identification string (e.g., "SSH-2.0-OpenSSH_8.9")
    std::string software_version;     // Extracted software version (e.g., "OpenSSH_8.9")
    std::string protocol_version;     // Extracted protocol version (e.g., "2.0")
    
    // SSH handshake message fields
    uint8_t handshake_message_type = 0; // SSH handshake message type code
    std::string handshake_type_str;   // Human-readable message type string
    size_t packet_length = 0;         // SSH packet length
    size_t padding_length = 0;        // SSH padding length
    size_t message_content_length = 0; // SSH message content length
    
    // SSH key exchange init message fields (when applicable)
    std::string cookie_hex;           // 16-byte cookie as hex string
    std::string key_exchange_algorithms;      // Supported key exchange algorithms
    std::string server_host_key_algorithms;   // Supported server host key algorithms
    std::string encryption_algorithms_client_to_server;  // Client->Server encryption algorithms
    std::string encryption_algorithms_server_to_client;  // Server->Client encryption algorithms
    std::string mac_algorithms_client_to_server;         // Client->Server MAC algorithms
    std::string mac_algorithms_server_to_client;         // Server->Client MAC algorithms
    std::string compression_algorithms_client_to_server; // Client->Server compression algorithms
    std::string compression_algorithms_server_to_client; // Server->Client compression algorithms
    std::string languages_client_to_server;              // Client->Server language tags
    std::string languages_server_to_client;              // Server->Client language tags
    bool first_kex_packet_follows = false;               // First KEX packet follows flag
    
    // General SSH information
    size_t total_message_length = 0;  // Total length of SSH message
    std::string message_preview;      // Preview of message content (first 100 chars)
    std::string session_info;         // Session information summary
    
    // Helper methods
    std::string getMessageTypeString() const {
        return message_type.empty() ? "UNKNOWN" : message_type;
    }
    
    std::string getHandshakeTypeString() const {
        return handshake_type_str.empty() ? "Unknown" : handshake_type_str;
    }
    
    std::string getIdentificationInfo() const {
        if (identification_string.empty()) {
            return "No identification";
        }
        std::ostringstream oss;
        oss << "Protocol: " << protocol_version;
        if (!software_version.empty()) {
            oss << ", Software: " << software_version;
        }
        return oss.str();
    }
    
    std::string getKeyExchangeInfo() const {
        if (!is_key_exchange) {
            return "Not a key exchange message";
        }
        std::ostringstream oss;
        if (!key_exchange_algorithms.empty()) {
            oss << "KEX: " << key_exchange_algorithms << "; ";
        }
        if (!encryption_algorithms_client_to_server.empty()) {
            oss << "Encryption: " << encryption_algorithms_client_to_server << "; ";
        }
        if (!mac_algorithms_client_to_server.empty()) {
            oss << "MAC: " << mac_algorithms_client_to_server;
        }
        return oss.str();
    }
    
    std::string getSessionInfo() const {
        std::ostringstream oss;
        oss << message_type;
        if (is_identification && !software_version.empty()) {
            oss << " (" << software_version << ")";
        } else if (is_key_exchange) {
            oss << " (negotiating algorithms)";
        }
        return oss.str();
    }
};

// BGP metadata
struct BGPMetadata {
    // BGP Header fields (RFC 4271)
    std::string marker;               // 16-byte marker (all 1s for authentication)
    uint16_t length = 0;              // Total length of BGP message
    uint8_t type = 0;                 // BGP message type
    
    // BGP Message Type constants
    static const uint8_t OPEN = 1;
    static const uint8_t UPDATE = 2;
    static const uint8_t NOTIFICATION = 3;
    static const uint8_t KEEPALIVE = 4;
    static const uint8_t ROUTE_REFRESH = 5;
    
    // BGP OPEN message fields
    uint8_t version = 0;              // BGP version number
    uint16_t my_as = 0;               // My Autonomous System number
    uint16_t hold_time = 0;           // Hold time in seconds
    std::string bgp_identifier;       // BGP Identifier (Router ID)
    std::vector<std::string> optional_parameters; // Optional parameters
    
    // BGP UPDATE message fields
    std::vector<std::string> withdrawn_routes;     // Withdrawn routes (NLRI)
    std::vector<std::string> path_attributes;     // Path attributes
    std::vector<std::string> nlri;                 // Network Layer Reachability Information
    
    // BGP NOTIFICATION message fields
    uint8_t error_code = 0;           // Error code
    uint8_t error_subcode = 0;        // Error subcode
    std::string error_data;           // Error data (context)
    
    // BGP ROUTE-REFRESH message fields
    uint16_t afi = 0;                 // Address Family Identifier
    uint8_t safi = 0;                 // Sub-Address Family Identifier
    uint8_t reserved = 0;             // Reserved field
    
    // Path Attributes (common ones)
    std::string origin;               // ORIGIN attribute
    std::string as_path;              // AS_PATH attribute
    std::string next_hop;             // NEXT_HOP attribute
    uint32_t local_pref = 0;          // LOCAL_PREF attribute
    uint32_t med = 0;                 // MED (MULTI_EXIT_DISC) attribute
    std::string community;            // COMMUNITY attribute
    std::string mp_reach_nlri;        // MP_REACH_NLRI attribute
    std::string mp_unreach_nlri;      // MP_UNREACH_NLRI attribute
    
    // Message type string
    std::string type_str;             // Human-readable message type
    
    // Helper methods
    std::string getMessageTypeString() const {
        switch (type) {
            case OPEN: return "OPEN";
            case UPDATE: return "UPDATE";
            case NOTIFICATION: return "NOTIFICATION";
            case KEEPALIVE: return "KEEPALIVE";
            case ROUTE_REFRESH: return "ROUTE-REFRESH";
            default: return "UNKNOWN(" + std::to_string(type) + ")";
        }
    }
    
    std::string getErrorDescription() const {
        if (type != NOTIFICATION) return "";
        
        std::string desc = "Error " + std::to_string(error_code) + "." + std::to_string(error_subcode);
        
        // Common error codes and subcodes
        switch (error_code) {
            case 1:
                desc += " (Message Header Error";
                switch (error_subcode) {
                    case 1: desc += " - Connection Not Synchronized)"; break;
                    case 2: desc += " - Bad Message Length)"; break;
                    case 3: desc += " - Bad Message Type)"; break;
                    default: desc += ")"; break;
                }
                break;
            case 2:
                desc += " (OPEN Message Error";
                switch (error_subcode) {
                    case 1: desc += " - Unsupported Version Number)"; break;
                    case 2: desc += " - Bad Peer AS)"; break;
                    case 3: desc += " - Bad BGP Identifier)"; break;
                    case 4: desc += " - Unsupported Optional Parameter)"; break;
                    case 5: desc += " - Authentication Failure)"; break;
                    case 6: desc += " - Unacceptable Hold Time)"; break;
                    default: desc += ")"; break;
                }
                break;
            case 3:
                desc += " (UPDATE Message Error";
                switch (error_subcode) {
                    case 1: desc += " - Malformed Attribute List)"; break;
                    case 2: desc += " - Unrecognized Well-known Attribute)"; break;
                    case 3: desc += " - Missing Well-known Attribute)"; break;
                    case 4: desc += " - Attribute Flags Error)"; break;
                    case 5: desc += " - Attribute Length Error)"; break;
                    case 6: desc += " - Invalid ORIGIN Attribute)"; break;
                    case 7: desc += " - AS Routing Loop)"; break;
                    case 8: desc += " - Invalid NEXT_HOP Attribute)"; break;
                    case 9: desc += " - Optional Attribute Error)"; break;
                    case 10: desc += " - Invalid Network Field)"; break;
                    case 11: desc += " - Malformed AS_PATH)"; break;
                    default: desc += ")"; break;
                }
                break;
            case 4:
                desc += " (Hold Timer Expired)";
                break;
            case 5:
                desc += " (Finite State Machine Error)";
                break;
            case 6:
                desc += " (Cease";
                switch (error_subcode) {
                    case 1: desc += " - Maximum Number of Prefixes Reached)"; break;
                    case 2: desc += " - Administrative Shutdown)"; break;
                    case 3: desc += " - Peer De-configured)"; break;
                    case 4: desc += " - Administrative Reset)"; break;
                    case 5: desc += " - Connection Rejected)"; break;
                    case 6: desc += " - Other Configuration Change)"; break;
                    case 7: desc += " - Connection Collision Resolution)"; break;
                    case 8: desc += " - Out of Resources)"; break;
                    default: desc += ")"; break;
                }
                break;
            default:
                desc += " (Unknown Error)";
                break;
        }
        
        if (!error_data.empty()) {
            desc += " Data: " + error_data;
        }
        
        return desc;
    }
    
    std::string getPathAttributesSummary() const {
        if (type != UPDATE || path_attributes.empty()) return "";
        
        std::string summary = "Attributes: ";
        for (size_t i = 0; i < path_attributes.size() && i < 5; i++) {
            if (i > 0) summary += ", ";
            summary += path_attributes[i];
        }
        if (path_attributes.size() > 5) {
            summary += " (+" + std::to_string(path_attributes.size() - 5) + " more)";
        }
        return summary;
    }
    
    std::string getNLRI() const {
        if (type != UPDATE || nlri.empty()) return "";
        
        std::string nlri_str = "NLRI: ";
        for (size_t i = 0; i < nlri.size() && i < 3; i++) {
            if (i > 0) nlri_str += ", ";
            nlri_str += nlri[i];
        }
        if (nlri.size() > 3) {
            nlri_str += " (+" + std::to_string(nlri.size() - 3) + " more)";
        }
        return nlri_str;
    }
};

// Certificate metadata for X.509 certificates parsed from ASN.1
struct CertificateMetadata {
    // Basic certificate information (TBSCertificate)
    uint32_t version = 0;                         // Certificate version (1, 2, or 3)
    std::string serial_number;                    // Certificate serial number (hex string)
    std::string signature_algorithm_oid;          // Signature algorithm OID
    std::string signature_algorithm_name;         // Signature algorithm name (e.g., "sha256WithRSAEncryption")
    
    // Issuer information
    std::string issuer;                           // Certificate issuer (CN, O, OU, etc.)
    std::string issuer_country;                   // Issuer country (C)
    std::string issuer_organization;              // Issuer organization (O)
    std::string issuer_organizational_unit;       // Issuer organizational unit (OU)
    std::string issuer_common_name;               // Issuer common name (CN)
    std::string issuer_state;                     // Issuer state (ST)
    std::string issuer_locality;                  // Issuer locality (L)
    std::string issuer_email;                     // Issuer email (E)
    
    // Validity period
    uint64_t not_valid_before = 0;                // Certificate not valid before (Unix timestamp)
    uint64_t not_valid_after = 0;                 // Certificate not valid after (Unix timestamp)
    std::string not_valid_before_str;             // Certificate not valid before (string format)
    std::string not_valid_after_str;              // Certificate not valid after (string format)
    
    // Subject information
    std::string subject;                          // Certificate subject (CN, O, OU, etc.)
    std::string subject_country;                  // Subject country (C)
    std::string subject_organization;             // Subject organization (O)
    std::string subject_organizational_unit;      // Subject organizational unit (OU)
    std::string subject_common_name;              // Subject common name (CN)
    std::string subject_state;                    // Subject state (ST)
    std::string subject_locality;                 // Subject locality (L)
    std::string subject_email;                    // Subject email (E)
    
    // Subject Public Key Info
    std::string key_algorithm_oid;                // Public key algorithm OID
    std::string key_algorithm_name;               // Public key algorithm name (e.g., "rsaEncryption")
    std::string key_type;                         // Key type (e.g., "rsa", "ecdsa", "dsa")
    uint32_t key_length = 0;                      // Key length in bits
    std::string exponent;                         // RSA exponent (e.g., "65537")
    std::string public_key_hex;                   // Public key in hex format
    std::string public_key_modulus;               // RSA modulus (for RSA keys)
    std::string public_key_exponent;              // RSA public exponent (for RSA keys)
    
    // Extensions (X.509 v3)
    bool has_extensions = false;                  // Whether certificate has extensions
    
    // Subject Alternative Name (SAN) extension
    std::vector<std::string> dns_names;           // DNS names from SAN extension
    std::vector<std::string> email_addresses;     // Email addresses from SAN extension
    std::vector<std::string> ip_addresses;        // IP addresses from SAN extension
    std::vector<std::string> uris;                // URIs from SAN extension
    std::vector<std::string> other_names;         // Other names from SAN extension
    
    // Key Usage extension
    bool key_usage_digital_signature = false;     // Digital signature key usage
    bool key_usage_non_repudiation = false;       // Non-repudiation key usage
    bool key_usage_key_encipherment = false;      // Key encipherment key usage
    bool key_usage_data_encipherment = false;     // Data encipherment key usage
    bool key_usage_key_agreement = false;         // Key agreement key usage
    bool key_usage_key_cert_sign = false;         // Key certificate sign key usage
    bool key_usage_crl_sign = false;              // CRL sign key usage
    bool key_usage_encipher_only = false;         // Encipher only key usage
    bool key_usage_decipher_only = false;         // Decipher only key usage
    
    // Extended Key Usage extension
    std::vector<std::string> extended_key_usage;  // Extended key usage OIDs
    bool ext_key_usage_server_auth = false;       // Server authentication
    bool ext_key_usage_client_auth = false;       // Client authentication
    bool ext_key_usage_code_signing = false;      // Code signing
    bool ext_key_usage_email_protection = false;  // Email protection
    bool ext_key_usage_time_stamping = false;     // Time stamping
    bool ext_key_usage_ocsp_signing = false;      // OCSP signing
    
    // Basic Constraints extension
    bool is_ca = false;                           // Whether this is a CA certificate
    int32_t path_length_constraint = -1;          // Path length constraint (-1 means no limit)
    
    // Authority Key Identifier extension
    std::string authority_key_id;                 // Authority key identifier
    std::string authority_cert_issuer;            // Authority certificate issuer
    std::string authority_cert_serial;            // Authority certificate serial number
    
    // Subject Key Identifier extension
    std::string subject_key_id;                   // Subject key identifier
    
    // CRL Distribution Points extension
    std::vector<std::string> crl_distribution_points; // CRL distribution points
    
    // Authority Information Access extension
    std::vector<std::string> ocsp_responders;     // OCSP responders
    std::vector<std::string> ca_issuers;          // CA issuers
    
    // Certificate Policies extension
    std::vector<std::string> certificate_policies; // Certificate policies
    
    // Policy Mappings extension
    std::vector<std::string> policy_mappings;     // Policy mappings
    
    // Name Constraints extension
    std::vector<std::string> permitted_subtrees;  // Permitted subtrees
    std::vector<std::string> excluded_subtrees;   // Excluded subtrees
    
    // Policy Constraints extension
    bool require_explicit_policy = false;         // Require explicit policy
    int32_t inhibit_policy_mapping = -1;          // Inhibit policy mapping (-1 means no limit)
    
    // Inhibit Any Policy extension
    int32_t inhibit_any_policy = -1;              // Inhibit any policy (-1 means no limit)
    
    // Freshest CRL extension
    std::vector<std::string> freshest_crl;        // Freshest CRL distribution points
    
    // Certificate fingerprinting
    std::string fingerprint_sha1;                 // SHA-1 fingerprint
    std::string fingerprint_sha256;               // SHA-256 fingerprint
    std::string fingerprint_md5;                  // MD5 fingerprint (deprecated)
    
    // Certificate validation
    bool is_self_signed = false;                  // Whether certificate is self-signed
    bool is_valid = false;                        // Whether certificate is valid
    std::string validation_error;                 // Validation error message
    
    // Raw ASN.1 data
    std::vector<uint8_t> raw_certificate;         // Raw certificate data
    std::string asn1_der_hex;                     // ASN.1 DER encoded certificate in hex
    
    // Helper methods
    std::string getVersionString() const;
    std::string getValidityString() const;
    std::string getKeyInfoString() const;
    std::string getSANString() const;
    std::string getKeyUsageString() const;
    std::string getExtendedKeyUsageString() const;
    std::string getIssuerString() const;
    std::string getSubjectString() const;
    std::string getFingerprintString() const;
    std::string getExtensionsString() const;
};

// SSL/TLS specific data structures for union
struct SSLHandshakeData {
    uint8_t handshake_type = 0;        // Handshake message type
    uint16_t handshake_version = 0;    // SSL/TLS version at handshake level
    uint32_t handshake_length = 0;     // Handshake message length
    
    // Client/Server Hello specific fields
    bool is_client_hello = false;      // Whether this is a Client Hello message
    bool is_server_hello = false;      // Whether this is a Server Hello message
    uint8_t session_id_length = 0;     // Session ID length
    std::vector<uint8_t> session_id;   // Session ID bytes
    
    // Cipher suite information
    std::vector<uint16_t> cipher_suites;           // List of cipher suite IDs
    std::string selected_cipher_suite;             // Selected cipher suite name
    uint16_t selected_cipher_suite_id = 0;        // Selected cipher suite ID
    
    // Compression methods
    uint8_t compression_methods_count = 0;         // Number of compression methods
    std::vector<uint8_t> compression_methods;     // Compression method values
    
    // Extensions
    std::vector<uint16_t> extension_types;        // Extension type IDs
    std::vector<std::string> extension_names;     // Extension names
    
    // Supported groups (elliptic curves)
    std::vector<uint16_t> supported_groups;       // Supported group IDs
    std::vector<std::string> supported_group_names; // Supported group names
    
    // EC point formats
    std::vector<uint8_t> ec_point_formats;        // EC point format values
    
    // Server name indication
    std::vector<std::string> server_names;        // Server names from SNI extension
    
    // Supported versions
    std::vector<uint16_t> supported_versions;     // Supported TLS versions
    
    // Random data
    std::vector<uint8_t> random_data;             // Random bytes (32 bytes for Hello messages)
    
    // Certificate information (if available)
    bool has_certificate = false;                 // Whether certificate is present
    uint16_t certificate_count = 0;               // Number of certificates
    std::vector<std::string> certificate_subjects; // Certificate subjects
    
    // X.509 Certificate metadata (parsed from ASN.1)
    std::vector<CertificateMetadata> certificates; // Parsed certificate information
    
    // TLS fingerprinting
    std::string client_hello_fingerprint;         // JA3 fingerprint for client hello
    std::string server_hello_fingerprint;         // JA3S fingerprint for server hello
};

struct SSLAlertData {
    uint8_t alert_level = 0;                      // Alert level
    uint8_t alert_description = 0;                // Alert description
};

struct SSLApplicationDataInfo {
    uint16_t application_data_length = 0;         // Application data length
    bool is_encrypted = true;                     // Application data is always encrypted
};

struct SSLChangeCipherSpecData {
    bool is_change_cipher_spec = true;           // Change cipher spec message
};

// SSL/TLS metadata with separate data structures for different types
struct SSLMetadata {
    // SSL/TLS record layer information (common to all types)
    uint8_t record_type = 0;           // SSL record type (handshake, alert, etc.)
    uint16_t record_version = 0;       // SSL/TLS version at record level
    uint16_t record_length = 0;        // Record length
    
    // Protocol state (common to all types)
    std::string ssl_state;                        // Current SSL/TLS state
    
    // SSL-specific data based on record type
    SSLHandshakeData handshake_data;
    SSLAlertData alert_data;
    SSLApplicationDataInfo application_data_info;
    SSLChangeCipherSpecData change_cipher_spec_data;
    
    // SSL layer type flags for different output formats
    bool is_handshake_layer = false;              // Whether this is a handshake layer
    bool is_change_cipher_spec_layer = false;     // Whether this is a change cipher spec layer
    bool is_alert_layer = false;                  // Whether this is an alert layer
    bool is_application_data_layer = false;       // Whether this is an application data layer
    
    // Helper methods
    std::string getRecordTypeString() const;
    std::string getHandshakeTypeString() const;
    std::string getVersionString() const;
    std::string getCipherSuitesString() const;
    std::string getExtensionsString() const;
    std::string getSupportedGroupsString() const;
    std::string getRandomDataString() const;
    std::string getSessionIDString() const;
};

// IPSec ESP metadata
struct ESPMetadata {
    uint32_t spi = 0;                    // Security Parameters Index
    uint32_t sequence_number = 0;       // Sequence Number
    size_t header_length = 0;            // ESP header length (8 bytes)
    size_t payload_length = 0;           // Encrypted payload length
    size_t trailer_length = 0;           // ESP trailer length (padding + pad length + next header)
    uint8_t next_header = 0;             // Next header protocol (from trailer)
    bool is_encrypted = true;            // ESP payload is always encrypted
    
    // Helper methods
    std::string getSPIString() const {
        return "0x" + std::to_string(spi);
    }
    
    std::string getSequenceString() const {
        return std::to_string(sequence_number);
    }
    
    std::string getNextHeaderString() const {
        switch (next_header) {
            case 1: return "ICMP";
            case 2: return "IGMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 41: return "IPv6";
            case 47: return "GRE";
            case 50: return "ESP";
            case 51: return "AH";
            case 58: return "ICMPv6";
            case 89: return "OSPF";
            default: return "Unknown(" + std::to_string(next_header) + ")";
        }
    }
    
    std::string getInfoString() const {
        std::ostringstream oss;
        oss << "SPI: " << getSPIString() 
            << ", Seq: " << getSequenceString()
            << ", Next: " << getNextHeaderString();
        return oss.str();
    }
};

// IPSec AH metadata
struct AHMetadata {
    uint8_t next_header = 0;            // Next header protocol
    uint8_t payload_length = 0;         // Payload length in 4-octet units, minus 2
    uint16_t reserved = 0;              // Reserved field
    uint32_t spi = 0;                   // Security Parameters Index
    uint32_t sequence_number = 0;       // Sequence Number
    size_t header_length = 0;            // AH header length (variable, based on payload_length)
    size_t icv_length = 0;              // Integrity Check Value length
    std::string icv_hex;                 // ICV as hex string
    
    // Helper methods
    std::string getSPIString() const {
        return "0x" + std::to_string(spi);
    }
    
    std::string getSequenceString() const {
        return std::to_string(sequence_number);
    }
    
    std::string getNextHeaderString() const {
        switch (next_header) {
            case 1: return "ICMP";
            case 2: return "IGMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 41: return "IPv6";
            case 47: return "GRE";
            case 50: return "ESP";
            case 51: return "AH";
            case 58: return "ICMPv6";
            case 89: return "OSPF";
            default: return "Unknown(" + std::to_string(next_header) + ")";
        }
    }
    
    std::string getICVString() const {
        if (icv_hex.empty()) {
            return "None";
        }
        return icv_hex.substr(0, 16) + (icv_hex.length() > 16 ? "..." : "");
    }
    
    std::string getInfoString() const {
        std::ostringstream oss;
        oss << "SPI: " << getSPIString() 
            << ", Seq: " << getSequenceString()
            << ", Next: " << getNextHeaderString()
            << ", ICV: " << getICVString();
        return oss.str();
    }
};

// Telnet metadata
struct TelnetMetadata {
    // Basic Telnet information
    bool is_control = false;          // True if contains control commands
    bool is_text = false;             // True if contains text data
    std::string type;                 // "CONTROL", "TEXT", or "MIXED"
    
    // Control command information
    size_t command_count = 0;         // Number of IAC commands found
    std::vector<std::string> commands; // List of parsed commands
    std::string command_summary;      // Summary of all commands
    
    // Text data information
    size_t text_length = 0;           // Length of text data
    std::string text_preview;         // Preview of text content (first 100 chars)
    std::string filtered_text;        // Text with control characters filtered
    
    // Session information
    std::string session_type;         // "CLIENT" or "SERVER"
    bool is_negotiation = false;      // True if this is option negotiation
    
    // Data statistics
    size_t total_data_length = 0;     // Total length of all data
    size_t iac_sequences = 0;         // Number of IAC sequences found
    size_t text_sequences = 0;        // Number of text sequences found
    
    // Helper methods
    std::string getTypeString() const {
        return type.empty() ? "UNKNOWN" : type;
    }
    
    std::string getCommandSummary() const {
        return command_summary.empty() ? "No commands" : command_summary;
    }
    
    std::string getTextPreview() const {
        return text_preview.empty() ? "No text data" : text_preview;
    }
    
    bool hasCommands() const {
        return command_count > 0;
    }
    
    bool hasText() const {
        return text_length > 0;
    }
    
    std::string getSessionInfo() const {
        std::ostringstream oss;
        oss << session_type;
        if (is_negotiation) {
            oss << " (negotiating)";
        }
        return oss.str();
    }
};

// Main packet metadata structure
struct PacketMetadata
{
    // Basic metadata
    double timestamp = 0.0;
    size_t packet_length = 0;
    size_t payload_length = 0;
    
    // Protocol presence flags
    bool has_ethernet = false;
    bool has_vlan = false;
    bool has_gre = false;
    bool has_vxlan = false;
    bool has_wifi = false;
    bool has_ipv4 = false;
    bool has_ipv6 = false;
    bool has_tcp = false;
    bool has_udp = false;
    bool has_arp = false;
    bool has_icmp = false;
    bool has_icmpv6 = false;
    bool has_igmp = false;
    bool has_mpls = false;
    bool has_ndp = false;
    bool has_vrrp = false;
    bool has_http = false;
    bool has_dns = false;
    bool has_ftp = false;
    bool has_smtp = false;
    bool has_telnet = false;
    bool has_dhcp = false;
    bool has_dhcpv6 = false;
    bool has_ntp = false;
    bool has_ssh = false;
    bool has_bgp = false;
    bool has_ssl = false; // Added for SSL/TLS
    bool has_esp = false; // Added for IPSec ESP
    bool has_ah = false;  // Added for IPSec AH
    
    // Protocol metadata structures
    EthernetMetadata ethernet;
    VLANMetadata vlan;
    MPLSMetadata mpls;
    GREMetadata gre;
    VXLANMetadata vxlan;
    WiFiMetadata wifi;
    IPv4Metadata ipv4;
    IPv6Metadata ipv6;
    TCPMetadata tcp;
    UDPMetadata udp;
    ARPMetadata arp;
    ICMPMetadata icmp;
    ICMPv6Metadata icmpv6;
    IGMPMetadata igmp;
    NDPMetadata ndp;
    VRRPMetadata vrrp;
    HTTPMetadata http;
    DNSMetadata dns;
    FTPMetadata ftp;
    SMTPMetadata smtp;
    TelnetMetadata telnet;
    DHCPMetadata dhcp;
    DHCPv6Metadata dhcpv6;
    NTPMetadata ntp;
    SSHMetadata ssh;
    BGPMetadata bgp;
    SSLMetadata ssl; // Added for SSL/TLS
    ESPMetadata esp; // Added for IPSec ESP
    AHMetadata ah;   // Added for IPSec AH
    
    // Legacy fields for backward compatibility
    std::string srcIP;
    std::string dstIP;
    std::string protocol;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    
    std::string application_protocol; // Application layer protocol: ssh, smtp, http, etc.

private:
    /**
     * @brief Convert IP address from uint32_t to string format
     * @param ip IP address in network byte order
     * @return IP address as string
     */
    static std::string ipToString(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return inet_ntoa(addr);
    }

public:
    std::string toString() const;
};

#endif