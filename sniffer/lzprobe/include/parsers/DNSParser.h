#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "BaseParser.h"
#include <pcapplusplus/DnsLayer.h>

/**
 * @brief DNS (Domain Name System) Protocol Parser
 * 
 * This parser handles DNS protocol packets using PcapPlusplus DnsLayer.
 * 
 * DNS packet structure:
 * - Header: Transaction ID, Flags, Question/Answer/Authority/Additional counts
 * - Question: Domain name, query type, query class
 * - Answer: Resource records with domain resolution results
 * - Authority: Authoritative server information if no direct answer
 * - Additional: Additional records (like IP addresses of authoritative servers)
 * 
 * Supports both DNS queries and responses with comprehensive flag parsing.
 */
class DNSParser : public BaseParser {
public:
    /**
     * @brief Parse DNS packet and fill metadata
     * @param packet The packet to parse (must contain DNS layer)
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * @brief Parse DNS header section using PcapPlusplus DnsLayer
     * @param header Pointer to DNS header structure
     * @param metadata The metadata structure to fill
     */
    static void parseHeader(const pcpp::dnshdr* header, PacketMetadata& metadata);
    
    /**
     * @brief Parse DNS questions using PcapPlusplus DnsLayer
     * @param dnsLayer Pointer to DNS layer
     * @param metadata The metadata structure to fill
     */
    static void parseQuestions(pcpp::DnsLayer* dnsLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse DNS resource records using PcapPlusplus DnsLayer
     * @param dnsLayer Pointer to DNS layer
     * @param sectionType Type of section to parse (DnsAnswerType, DnsAuthorityType, DnsAdditionalType)
     * @param records Vector to store parsed resource records
     */
    static void parseResourceRecords(pcpp::DnsLayer* dnsLayer, pcpp::DnsResourceType sectionType, 
                                   std::vector<DNSMetadata::DNSResourceRecord>& records);
    
    /**
     * @brief Parse resource data based on record type using PcapPlusplus classes
     * @param resource Pointer to DNS resource record
     * @param record Output resource record structure to fill
     */
    static void parseResourceData(pcpp::DnsResource* resource, DNSMetadata::DNSResourceRecord& record);
    
    /**
     * @brief Check if packet is likely a DNS packet based on port and DNS layer presence
     * @param packet The packet to check
     * @return true if packet appears to be DNS
     */
    static bool isDNSPacket(pcpp::Packet& packet);

public:
    /**
     * @brief Format DNS opcode to string
     * @param dns_meta The DNS metadata containing opcode
     * @return Formatted opcode string
     */
    static std::string getOpcodeString(const DNSMetadata& dns_meta);

    /**
     * @brief Format DNS response code to string
     * @param dns_meta The DNS metadata containing rcode
     * @return Formatted response code string
     */
    static std::string getRcodeString(const DNSMetadata& dns_meta);

    /**
     * @brief Format DNS query type to string
     * @param dns_meta The DNS metadata containing qtype
     * @return Formatted query type string
     */
    static std::string getQtypeString(const DNSMetadata& dns_meta);

    /**
     * @brief Format DNS query class to string
     * @param dns_meta The DNS metadata containing qclass
     * @return Formatted query class string
     */
    static std::string getQclassString(const DNSMetadata& dns_meta);

    /**
     * @brief Format DNS record type to string
     * @param type DNS record type code
     * @return Formatted type string
     */
    static std::string getTypeString(uint16_t type);

    /**
     * @brief Format DNS flags to string
     * @param dns_meta The DNS metadata containing flags
     * @return Formatted flags string
     */
    static std::string getFlagsString(const DNSMetadata& dns_meta);
};

#endif // DNS_PARSER_H
