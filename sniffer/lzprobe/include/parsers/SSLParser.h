#ifndef SSL_PARSER_H
#define SSL_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLCommon.h>
#include <pcapplusplus/Asn1Codec.h>
#include <map>
#include <sstream>
#include <iomanip>
#include <ctime>

/**
 * @brief Parser for SSL/TLS protocol packets
 * 
 * This parser handles SSL/TLS protocol analysis using PcapPlusPlus library.
 * SSL/TLS operates over TCP with well-known ports:
 * - Port 443: HTTPS
 * - Port 465: SMTPS
 * - Port 563: NNTPS
 * - Port 636: LDAPS
 * - Port 989: FTPS-data
 * - Port 990: FTPS-control
 * - Port 992: Telnet over TLS/SSL
 * - Port 993: IMAPS
 * - Port 994: IRCS
 * - Port 995: POP3S
 * 
 * SSL/TLS packet identification:
 * 1. Ethernet layer: EtherType = 0x0800 (IPv4) or 0x86DD (IPv6)
 * 2. Network layer: IPv4/IPv6 next header = 6 (TCP)
 * 3. Transport layer: TCP port (one of the SSL/TLS ports)
 * 4. Application layer: SSL/TLS record layer
 */
class SSLParser : public BaseParser {
public:
    /**
     * @brief Parse SSL/TLS packet and extract metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * @brief Parse SSL/TLS record layer
     * @param sslLayer The SSL layer to parse
     * @param metadata The metadata structure to fill
     * @return true if record layer parsing was successful
     */
    static bool parseRecordLayer(pcpp::SSLLayer* sslLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS handshake layer
     * @param handshakeLayer The handshake layer to parse
     * @param metadata The metadata structure to fill
     * @return true if handshake layer parsing was successful
     */
    static bool parseHandshakeLayer(pcpp::SSLHandshakeLayer* handshakeLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS client hello message
     * @param clientHello The client hello message to parse
     * @param metadata The metadata structure to fill
     * @return true if client hello parsing was successful
     */
    static bool parseClientHello(pcpp::SSLClientHelloMessage* clientHello, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS server hello message
     * @param serverHello The server hello message to parse
     * @param metadata The metadata structure to fill
     * @return true if server hello parsing was successful
     */
    static bool parseServerHello(pcpp::SSLServerHelloMessage* serverHello, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS certificate message
     * @param certMessage The certificate message to parse
     * @param metadata The metadata structure to fill
     * @return true if certificate parsing was successful
     */
    static bool parseCertificate(pcpp::SSLCertificateMessage* certMessage, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS alert message
     * @param alertLayer The alert layer to parse
     * @param metadata The metadata structure to fill
     * @return true if alert parsing was successful
     */
    static bool parseAlert(pcpp::SSLAlertLayer* alertLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS change cipher spec message
     * @param changeCipherLayer The change cipher spec layer to parse
     * @param metadata The metadata structure to fill
     * @return true if change cipher spec parsing was successful
     */
    static bool parseChangeCipherSpec(pcpp::SSLChangeCipherSpecLayer* changeCipherLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS application data
     * @param appDataLayer The application data layer to parse
     * @param metadata The metadata structure to fill
     * @return true if application data parsing was successful
     */
    static bool parseApplicationData(pcpp::SSLApplicationDataLayer* appDataLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSL/TLS extensions
     * @param handshakeMsg The handshake message containing extensions
     * @param metadata The metadata structure to fill
     * @return true if extensions parsing was successful
     */
    static bool parseExtensions(pcpp::SSLHandshakeMessage* handshakeMsg, PacketMetadata& metadata);
    
    /**
     * @brief Parse X.509 certificate using ASN.1
     * @param rootRecord The ASN.1 root record of the certificate
     * @param metadata The metadata structure to fill
     * @param certIndex The index of the certificate in the chain
     */
    static void parseX509Certificate(pcpp::Asn1SequenceRecord* rootRecord, PacketMetadata& metadata, int certIndex);
    
    /**
     * @brief Parse TBSCertificate (To Be Signed Certificate)
     * @param tbsCert The TBSCertificate ASN.1 record
     * @param cert The certificate metadata structure to fill
     */
    static void parseTBSCertificate(pcpp::Asn1SequenceRecord* tbsCert, CertificateMetadata& cert);
    
    /**
     * @brief Parse signature algorithm
     * @param sigAlg The signature algorithm ASN.1 record
     * @param cert The certificate metadata structure to fill
     */
    static void parseSignatureAlgorithm(pcpp::Asn1SequenceRecord* sigAlg, CertificateMetadata& cert);
    
    /**
     * @brief Parse certificate name (issuer or subject)
     * @param name The name ASN.1 record
     * @param result The string to store the parsed name
     * @param type The type of name ("issuer" or "subject")
     */
    static void parseName(pcpp::Asn1SequenceRecord* name, std::string& result, const std::string& type);
    
    /**
     * @brief Parse certificate validity period
     * @param validity The validity ASN.1 record
     * @param cert The certificate metadata structure to fill
     */
    static void parseValidity(pcpp::Asn1SequenceRecord* validity, CertificateMetadata& cert);
    
    /**
     * @brief Parse subject public key information
     * @param pubKeyInfo The public key info ASN.1 record
     * @param cert The certificate metadata structure to fill
     */
    static void parseSubjectPublicKeyInfo(pcpp::Asn1SequenceRecord* pubKeyInfo, CertificateMetadata& cert);
    
    /**
     * @brief Parse certificate extensions
     * @param extensions The extensions ASN.1 record
     * @param cert The certificate metadata structure to fill
     */
    static void parseExtensions(pcpp::Asn1SequenceRecord* extensions, CertificateMetadata& cert);
    
    /**
     * @brief Get signature algorithm name from OID
     * @param oid The algorithm OID
     * @return Human-readable algorithm name
     */
    static std::string getSignatureAlgorithmName(const std::string& oid);
    
    /**
     * @brief Get key algorithm name from OID
     * @param oid The algorithm OID
     * @return Human-readable algorithm name
     */
    static std::string getKeyAlgorithmName(const std::string& oid);
    
    /**
     * @brief Get attribute name from OID
     * @param oid The attribute OID
     * @return Human-readable attribute name
     */
    static std::string getAttributeName(const std::string& oid);
    
    /**
     * @brief Parse UTC time string to time_t
     * @param utcTimeStr The UTC time string (format: YYMMDDHHMMSSZ)
     * @return time_t value
     */
    static time_t parseUtcTime(const std::string& utcTimeStr);
    
    /**
     * @brief Convert bytes to hex string
     * @param bytes The bytes to convert
     * @return Hex string representation
     */
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    
public:
    /**
     * @brief Get SSL/TLS record type string
     * @param recordType The record type value
     * @return Human-readable record type string
     */
    static std::string getRecordTypeString(uint8_t recordType);
    
    /**
     * @brief Get SSL/TLS handshake type string
     * @param handshakeType The handshake type value
     * @return Human-readable handshake type string
     */
    static std::string getHandshakeTypeString(uint8_t handshakeType);
    
    /**
     * @brief Get SSL/TLS version string
     * @param version The version value
     * @return Human-readable version string
     */
    static std::string getVersionString(uint16_t version);
    
    /**
     * @brief Get cipher suite name by ID
     * @param cipherSuiteId The cipher suite ID
     * @return Cipher suite name or "Unknown" if not found
     */
    static std::string getCipherSuiteName(uint16_t cipherSuiteId);
    
    // /**
    //  * @brief Get extension name by type
    //  * @param extensionType The extension type value
    //  * @return Extension name or "Unknown" if not found
    //  */
    // static std::string getExtensionName(uint16_t extensionType);
    
    /**
     * @brief Get supported group name by ID
     * @param groupId The supported group ID
     * @return Group name or "Unknown" if not found
     */
    static std::string getSupportedGroupName(uint16_t groupId);
    
    /**
     * @brief Convert bytes to hex string
     * @param data Pointer to data bytes
     * @param length Length of data
     * @param maxBytes Maximum bytes to show (0 = show all)
     * @return Hex string representation
     */
    static std::string bytesToHexString(const uint8_t* data, size_t length, size_t maxBytes = 0);

public:
    /**
     * @brief Formats SSL metadata for CSV output
     * @param ssl_meta The SSL metadata to format
     * @param line The output stream to write to
     * @param separator The field separator to use
     */
    static void formatForCSV(const SSLMetadata& ssl_meta, std::ostringstream& line, const std::string& separator);

    /**
     * @brief Formats SSL metadata for JSON output
     * @param ssl_meta The SSL metadata to format
     * @param oss The output stream to write to
     * @param escapeJsonString Function to escape JSON strings
     */
    static void formatForJSON(const SSLMetadata& ssl_meta, std::ostringstream& oss, 
                             std::function<std::string(const std::string&)> escapeJsonString);

private:
    /**
     * @brief Manually parse SSL/TLS data
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parseManualSSL(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Validate SSL record format
     * @param contentType SSL content type
     * @param version SSL version
     * @param length Record length
     * @param payloadSize TCP payload size
     * @return true if record format is valid, false otherwise
     */
    static bool isValidSSLRecord(uint8_t contentType, uint16_t version, uint16_t length, size_t payloadSize);
    
    /**
     * @brief Manually parse SSL handshake message
     * @param handshakeData Handshake data pointer
     * @param handshakeLength Handshake data length
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parseManualHandshake(const uint8_t* handshakeData, uint16_t handshakeLength, PacketMetadata& metadata);
    
    /**
     * @brief Manually parse Client Hello message
     * @param clientHelloData Client Hello data pointer
     * @param clientHelloLength Client Hello data length
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parseManualClientHello(const uint8_t* clientHelloData, uint32_t clientHelloLength, PacketMetadata& metadata);
    
    /**
     * @brief Manually parse Server Hello message
     * @param serverHelloData Server Hello data pointer
     * @param serverHelloLength Server Hello data length
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parseManualServerHello(const uint8_t* serverHelloData, uint32_t serverHelloLength, PacketMetadata& metadata);
    
    /**
     * @brief Manually parse Certificate message
     * @param certData Certificate data pointer
     * @param certLength Certificate data length
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parseManualCertificate(const uint8_t* certData, uint32_t certLength, PacketMetadata& metadata);
    
    /**
     * @brief Manually parse Alert message
     * @param alertData Alert data pointer
     * @param alertLength Alert data length
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parseManualAlert(const uint8_t* alertData, uint16_t alertLength, PacketMetadata& metadata);
    
    /**
     * @brief Manually parse SSL extensions
     * @param extData Extension data pointer
     * @param extLength Extension data length
     * @param metadata The metadata structure to fill
     */
    static void parseManualExtensions(const uint8_t* extData, uint16_t extLength, PacketMetadata& metadata);
    
    /**
     * @brief Manually parse SNI extension
     * @param sniData SNI data pointer
     * @param sniLength SNI data length
     * @param metadata The metadata structure to fill
     */
    static void parseManualSNI(const uint8_t* sniData, uint16_t sniLength, PacketMetadata& metadata);
};

#endif // SSL_PARSER_H
