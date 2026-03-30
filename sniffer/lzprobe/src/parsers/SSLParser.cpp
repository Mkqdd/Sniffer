#include "parsers/SSLParser.h"
#include "LoggerManager.h"
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLCommon.h>
// #include <pcapplusplus/Asn1Codec.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <iostream>
#include <sstream>
#include <iomanip>

bool SSLParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First try manual parsing of SSL/TLS data from TCP payload
    if (parseManualSSL(packet, metadata)) {
        metadata.protocol = "TCP";
        metadata.application_protocol = "ssl";
        metadata.has_ssl = true;
        return true;
    }

    // If manual parsing fails, fall back to original library parsing method
    // Check for any SSL layer type (SSLLayer is abstract, so we check derived classes)
    auto* handshakeLayer = packet.getLayerOfType<pcpp::SSLHandshakeLayer>();
    auto* changeCipherLayer = packet.getLayerOfType<pcpp::SSLChangeCipherSpecLayer>();
    auto* alertLayer = packet.getLayerOfType<pcpp::SSLAlertLayer>();
    auto* appDataLayer = packet.getLayerOfType<pcpp::SSLApplicationDataLayer>();

    // Get the first available SSL layer for record layer parsing
    pcpp::SSLLayer* sslLayer = nullptr;
    if (handshakeLayer) {
        sslLayer = handshakeLayer;
    } else if (changeCipherLayer) {
        sslLayer = changeCipherLayer;
    } else if (alertLayer) {
        sslLayer = alertLayer;
    } else if (appDataLayer) {
        sslLayer = appDataLayer;
    }
    
    // Set protocol type and SSL flag
    metadata.protocol = "TCP";
    metadata.application_protocol = "ssl";
    metadata.has_ssl = true;
    
    // Parse SSL record layer
    if (!parseRecordLayer(sslLayer, metadata)) {
        return false;
    }
    // Set SSL layer type flags for different output formats
    if (handshakeLayer) {
        metadata.ssl.is_handshake_layer = true;
        parseHandshakeLayer(handshakeLayer, metadata);
    }
    
    if (changeCipherLayer) {
        metadata.ssl.is_change_cipher_spec_layer = true;
        parseChangeCipherSpec(changeCipherLayer, metadata);
    }
    
    if (alertLayer) {
        metadata.ssl.is_alert_layer = true;
        parseAlert(alertLayer, metadata);
    }
    
    if (appDataLayer) {
        metadata.ssl.is_application_data_layer = true;
        parseApplicationData(appDataLayer, metadata);
    }
    
    // Parse certificate layer if present
    pcpp::SSLCertificateMessage* certLayer = packet.getLayerOfType<pcpp::SSLCertificateMessage>();
    if (certLayer) {
        parseCertificate(certLayer, metadata);
    }
    
    return true;
}

bool SSLParser::parseRecordLayer(pcpp::SSLLayer* sslLayer, PacketMetadata& metadata) {
    if (!sslLayer) {
        return false;
    }
    // std::cout << "yes" << " ";
    // Get record layer information
    pcpp::ssl_tls_record_layer* record = sslLayer->getRecordLayer();
    if (!record) {
        return false;
    }
    
    metadata.ssl.record_type = record->recordType;
    std::cout << metadata.ssl.record_type << "2 ";
    metadata.ssl.record_version = record->recordVersion;
    metadata.ssl.record_length = record->length;
    
    return true;
}

bool SSLParser::parseHandshakeLayer(pcpp::SSLHandshakeLayer* handshakeLayer, PacketMetadata& metadata) {
    if (!handshakeLayer) {
        return false;
    }
    
    // Get handshake message count
    int handshakeMsgCount = handshakeLayer->getHandshakeMessagesCount();
    if (handshakeMsgCount == 0) {
        return false;
    }
    
    // Parse first handshake message
    pcpp::SSLHandshakeMessage* handshakeMsg = handshakeLayer->getHandshakeMessageAt(0);
    if (!handshakeMsg) {
        return false;
    }
    
    metadata.ssl.handshake_data.handshake_type = handshakeMsg->getHandshakeType();
    
    // Get handshake version and length
    metadata.ssl.handshake_data.handshake_version = 0x0303; // Default TLS 1.2, actual value obtained from specific message
    metadata.ssl.handshake_data.handshake_length = handshakeMsg->getMessageLength();
    
    // Parse Client Hello
    if (handshakeMsg->getHandshakeType() == pcpp::SSL_CLIENT_HELLO) {
        pcpp::SSLClientHelloMessage* clientHello = dynamic_cast<pcpp::SSLClientHelloMessage*>(handshakeMsg);
        if (clientHello) {
            parseClientHello(clientHello, metadata);
        }
    }
    
    // Parse Server Hello
    if (handshakeMsg->getHandshakeType() == pcpp::SSL_SERVER_HELLO) {
        pcpp::SSLServerHelloMessage* serverHello = dynamic_cast<pcpp::SSLServerHelloMessage*>(handshakeMsg);
        if (serverHello) {
            parseServerHello(serverHello, metadata);
        }
    }
    
    // Parse Certificate message
    if (handshakeMsg->getHandshakeType() == pcpp::SSL_CERTIFICATE) {
        pcpp::SSLCertificateMessage* certMessage = dynamic_cast<pcpp::SSLCertificateMessage*>(handshakeMsg);
        if (certMessage) {
            parseCertificate(certMessage, metadata);
        }
    }
    
    return true;
}

bool SSLParser::parseClientHello(pcpp::SSLClientHelloMessage* clientHello, PacketMetadata& metadata) {
    if (!clientHello) {
        return false;
    }
    
    metadata.ssl.handshake_data.is_client_hello = true;
    
    // Get Client Hello header
    pcpp::ssl_tls_client_server_hello* header = clientHello->getClientHelloHeader();
    if (header) {
        metadata.ssl.handshake_data.handshake_version = header->handshakeVersion;
        
        // Parse random data
        metadata.ssl.handshake_data.random_data.assign(header->random, header->random + 32);
    }
    
    // Parse session ID
    uint8_t sessionIdLength = clientHello->getSessionIDLength();
    metadata.ssl.handshake_data.session_id_length = sessionIdLength;
    if (sessionIdLength > 0) {
        const uint8_t* sessionId = clientHello->getSessionID();
        if (sessionId) {
            metadata.ssl.handshake_data.session_id.assign(sessionId, sessionId + sessionIdLength);
        }
    }
    
    // Parse cipher suites
    int cipherSuitesCount = clientHello->getCipherSuiteCount();
    metadata.ssl.handshake_data.cipher_suites.clear();
    for (int i = 0; i < cipherSuitesCount; i++) {
        bool isValid;
        uint16_t cipherSuite = clientHello->getCipherSuiteID(i, isValid);
        if (isValid) {
            metadata.ssl.handshake_data.cipher_suites.push_back(cipherSuite);
        }
    }
    
    // Parse compression methods
    uint8_t compressionMethod = clientHello->getCompressionMethodsValue();
    metadata.ssl.handshake_data.compression_methods_count = 1;
    metadata.ssl.handshake_data.compression_methods.clear();
    metadata.ssl.handshake_data.compression_methods.push_back(compressionMethod);
    
    // Parse extensions
    parseExtensions(clientHello, metadata);
    
    return true;
}

bool SSLParser::parseServerHello(pcpp::SSLServerHelloMessage* serverHello, PacketMetadata& metadata) {
    if (!serverHello) {
        return false;
    }
    
    metadata.ssl.handshake_data.is_server_hello = true;
    
    // Get Server Hello header
    pcpp::ssl_tls_client_server_hello* header = serverHello->getServerHelloHeader();
    if (header) {
        metadata.ssl.handshake_data.handshake_version = header->handshakeVersion;
        
        // Parse random data
        metadata.ssl.handshake_data.random_data.assign(header->random, header->random + 32);
    }
    
    // Parse session ID
    uint8_t sessionIdLength = serverHello->getSessionIDLength();
    metadata.ssl.handshake_data.session_id_length = sessionIdLength;
    if (sessionIdLength > 0) {
        const uint8_t* sessionId = serverHello->getSessionID();
        if (sessionId) {
            metadata.ssl.handshake_data.session_id.assign(sessionId, sessionId + sessionIdLength);
        }
    }
    
    // Parse selected cipher suite
    pcpp::SSLCipherSuite* selectedCipherSuite = serverHello->getCipherSuite();
    if (selectedCipherSuite) {
        metadata.ssl.handshake_data.selected_cipher_suite_id = selectedCipherSuite->getID();
        metadata.ssl.handshake_data.selected_cipher_suite = selectedCipherSuite->asString();
    }
    
    // Parse selected compression method
    uint8_t selectedCompressionMethod = serverHello->getCompressionMethodsValue();
    metadata.ssl.handshake_data.compression_methods.push_back(selectedCompressionMethod);
    metadata.ssl.handshake_data.compression_methods_count = 1;
    
    // Parse extensions
    parseExtensions(serverHello, metadata);
    
    return true;
}

bool SSLParser::parseCertificate(pcpp::SSLCertificateMessage* certMessage, PacketMetadata& metadata) {
    if (!certMessage) {
        return false;
    }
    
    metadata.ssl.handshake_data.has_certificate = true;
    
    // Get certificate count - PcapPlusPlus doesn't have getCertificateCount, so we'll try to get certificates one by one
    int certCount = 0;
    try {
        while (certMessage->getCertificate(certCount) != nullptr) {
            certCount++;
        }
    } catch (const std::exception& e) {
        // If we can't count certificates, assume at least one
        certCount = 1;
    }
    metadata.ssl.handshake_data.certificate_count = certCount;
    
    // Parse each certificate
    for (int i = 0; i < certCount; i++) {
        try {
            pcpp::SSLx509Certificate* cert = certMessage->getCertificate(i);
            if (cert) {
                // Try to parse certificate using ASN.1
                try {
                    pcpp::Asn1SequenceRecord* rootRecord = cert->getRootAsn1Record();
                    if (rootRecord) {
                        parseX509Certificate(rootRecord, metadata, i);
                    } else {
                        // Fallback to basic info
                        std::string subject = "Certificate_" + std::to_string(i) + "_" + std::to_string(cert->getDataLength());
                        metadata.ssl.handshake_data.certificate_subjects.push_back(subject);
                    }
                } catch (const std::exception& e) {
                    // If ASN.1 parsing fails, use fallback
                    std::string subject = "Certificate_" + std::to_string(i) + "_" + std::to_string(cert->getDataLength());
                    metadata.ssl.handshake_data.certificate_subjects.push_back(subject);
                }
            }
        } catch (const std::exception& e) {
            // If we can't get certificate at index i, break
            break;
        }
    }
    
    return true;
}

bool SSLParser::parseAlert(pcpp::SSLAlertLayer* alertLayer, PacketMetadata& metadata) {
    if (!alertLayer) {
        return false;
    }
    
    metadata.ssl.alert_data.alert_level = alertLayer->getAlertLevel();
    metadata.ssl.alert_data.alert_description = alertLayer->getAlertDescription();
    
    return true;
}

bool SSLParser::parseChangeCipherSpec(pcpp::SSLChangeCipherSpecLayer* changeCipherLayer, PacketMetadata& metadata) {
    if (!changeCipherLayer) {
        return false;
    }
    
    metadata.ssl.change_cipher_spec_data.is_change_cipher_spec = true;
    
    return true;
}

bool SSLParser::parseApplicationData(pcpp::SSLApplicationDataLayer* appDataLayer, PacketMetadata& metadata) {
    if (!appDataLayer) {
        return false;
    }
    
    metadata.ssl.application_data_info.application_data_length = appDataLayer->getDataLen();
    metadata.ssl.application_data_info.is_encrypted = true;
    
    return true;
}

void SSLParser::parseX509Certificate(pcpp::Asn1SequenceRecord* rootRecord, PacketMetadata& metadata, int certIndex) {
    if (!rootRecord) {
        return;
    }
    
    try {
        // X.509 certificate structure:
        // Certificate ::= SEQUENCE {
        //     tbsCertificate      TBSCertificate,
        //     signatureAlgorithm  AlgorithmIdentifier,
        //     signatureValue      BIT STRING
        // }
        
        auto& subRecords = rootRecord->getSubRecords();
        if (subRecords.size() < 3) {
            return;
        }
        
        // Ensure we have enough certificates in the vector
        while (metadata.ssl.handshake_data.certificates.size() <= static_cast<size_t>(certIndex)) {
            metadata.ssl.handshake_data.certificates.emplace_back();
        }
        
        // Parse TBSCertificate (first element)
        auto* tbsCert = subRecords.at(0)->castAs<pcpp::Asn1SequenceRecord>();
        if (tbsCert) {
            parseTBSCertificate(tbsCert, metadata.ssl.handshake_data.certificates[certIndex]);
        }
        
        // Parse signature algorithm (second element)
        auto* sigAlg = subRecords.at(1)->castAs<pcpp::Asn1SequenceRecord>();
        if (sigAlg) {
            parseSignatureAlgorithm(sigAlg, metadata.ssl.handshake_data.certificates[certIndex]);
        }
        
        // Parse signature value (third element) - use OctetString as fallback
        auto* sigValue = subRecords.at(2)->castAs<pcpp::Asn1OctetStringRecord>();
        if (sigValue) {
            std::string sigValueStr = sigValue->getValue();
            std::vector<uint8_t> sigValueBytes(sigValueStr.begin(), sigValueStr.end());
            metadata.ssl.handshake_data.certificates[certIndex].asn1_der_hex = bytesToHex(sigValueBytes);
        }
        
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

void SSLParser::parseTBSCertificate(pcpp::Asn1SequenceRecord* tbsCert, CertificateMetadata& cert) {
    if (!tbsCert) {
        return;
    }
    
    try {
        auto& subRecords = tbsCert->getSubRecords();
        if (subRecords.size() < 6) {
            return;
        }
        
        // Parse version (optional, first element if present)
        int offset = 0;
        
        if (subRecords.at(0)->getTagClass() == pcpp::Asn1TagClass::ContextSpecific && 
            subRecords.at(0)->getTagType() == 0) {
            // Version field is present
            // Version field is a constructed record, need to get the integer inside
            auto* versionConstructed = subRecords.at(0)->castAs<pcpp::Asn1ConstructedRecord>();
            if (versionConstructed) {
                auto& versionSubRecords = versionConstructed->getSubRecords();
                if (versionSubRecords.size() > 0) {
                    auto* version = versionSubRecords.at(0)->castAs<pcpp::Asn1IntegerRecord>();
                    if (version) {
                        cert.version = version->getValue();
                    }
                }
            }
            offset = 1;
        }
        
        // Parse serial number
        auto* serial = subRecords.at(offset)->castAs<pcpp::Asn1IntegerRecord>();
        if (serial) {
            std::ostringstream oss;
            oss << std::hex << serial->getValue();
            cert.serial_number = oss.str();
        }
        
        // Parse signature algorithm
        auto* sigAlg = subRecords.at(offset + 1)->castAs<pcpp::Asn1SequenceRecord>();
        if (sigAlg) {
            parseSignatureAlgorithm(sigAlg, cert);
        }
        
        // Parse issuer
        auto* issuer = subRecords.at(offset + 2)->castAs<pcpp::Asn1SequenceRecord>();
        if (issuer) {
            parseName(issuer, cert.issuer, "issuer");
        }
        
        // Parse validity
        auto* validity = subRecords.at(offset + 3)->castAs<pcpp::Asn1SequenceRecord>();
        if (validity) {
            parseValidity(validity, cert);
        }
        
        // Parse subject
        auto* subject = subRecords.at(offset + 4)->castAs<pcpp::Asn1SequenceRecord>();
        if (subject) {
            parseName(subject, cert.subject, "subject");
        }
        
        // Parse subject public key info
        auto* pubKeyInfo = subRecords.at(offset + 5)->castAs<pcpp::Asn1SequenceRecord>();
        if (pubKeyInfo) {
            parseSubjectPublicKeyInfo(pubKeyInfo, cert);
        }
        
        // Parse extensions (if present)
        if (subRecords.size() > static_cast<size_t>(offset + 6)) {
            auto* extensions = subRecords.at(offset + 6)->castAs<pcpp::Asn1SequenceRecord>();
            if (extensions) {
                parseExtensions(extensions, cert);
            }
        }
        
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

void SSLParser::parseSignatureAlgorithm(pcpp::Asn1SequenceRecord* sigAlg, CertificateMetadata& cert) {
    if (!sigAlg) {
        return;
    }
    
    try {
        auto& subRecords = sigAlg->getSubRecords();
        if (subRecords.size() >= 1) {
            // Try to get OID from OctetString as fallback since ObjectIdentifierRecord might not exist
            auto* oidRecord = subRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>();
            if (oidRecord) {
                std::string oidValue = oidRecord->getValue();
                cert.signature_algorithm_oid = oidValue;
                cert.signature_algorithm_name = getSignatureAlgorithmName(oidValue);
            }
        }
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

void SSLParser::parseName(pcpp::Asn1SequenceRecord* name, std::string& result, const std::string& type) {
    if (!name) {
        return;
    }
    
    try {
        std::ostringstream oss;
        auto& subRecords = name->getSubRecords();
        
        for (auto* record : subRecords) {
            auto* set = record->castAs<pcpp::Asn1SetRecord>();
            if (set) {
                auto& setRecords = set->getSubRecords();
                for (auto* setRecord : setRecords) {
                    auto* seq = setRecord->castAs<pcpp::Asn1SequenceRecord>();
                    if (seq) {
                        auto& seqRecords = seq->getSubRecords();
                        if (seqRecords.size() >= 2) {
                            // Use OctetString for both OID and value as fallback
                            auto* oidRecord = seqRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>();
                            auto* valueRecord = seqRecords.at(1)->castAs<pcpp::Asn1OctetStringRecord>();
                            if (oidRecord && valueRecord) {
                                std::string attrName = getAttributeName(oidRecord->getValue());
                                std::string attrValue = valueRecord->getValue();
                                if (!oss.str().empty()) oss << ", ";
                                oss << attrName << "=" << attrValue;
                            }
                        }
                    }
                }
            }
        }
        
        result = oss.str();
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

void SSLParser::parseValidity(pcpp::Asn1SequenceRecord* validity, CertificateMetadata& cert) {
    if (!validity) {
        return;
    }
    
    try {
        auto& subRecords = validity->getSubRecords();
        if (subRecords.size() >= 2) {
            // Parse notBefore - use OctetString as fallback
            auto* notBefore = subRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>();
            if (notBefore) {
                cert.not_valid_before_str = notBefore->getValue();
                cert.not_valid_before = parseUtcTime(notBefore->getValue());
            }
            
            // Parse notAfter - use OctetString as fallback
            auto* notAfter = subRecords.at(1)->castAs<pcpp::Asn1OctetStringRecord>();
            if (notAfter) {
                cert.not_valid_after_str = notAfter->getValue();
                cert.not_valid_after = parseUtcTime(notAfter->getValue());
            }
        }
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

void SSLParser::parseSubjectPublicKeyInfo(pcpp::Asn1SequenceRecord* pubKeyInfo, CertificateMetadata& cert) {
    if (!pubKeyInfo) {
        return;
    }
    
    try {
        auto& subRecords = pubKeyInfo->getSubRecords();
        if (subRecords.size() >= 2) {
            // Parse algorithm
            auto* alg = subRecords.at(0)->castAs<pcpp::Asn1SequenceRecord>();
            if (alg) {
                auto& algRecords = alg->getSubRecords();
                if (algRecords.size() >= 1) {
                    auto* oidRecord = algRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>();
                    if (oidRecord) {
                        cert.key_algorithm_oid = oidRecord->getValue();
                        cert.key_algorithm_name = getKeyAlgorithmName(oidRecord->getValue());
                    }
                }
            }
            
            // Parse public key - use OctetString as fallback
            auto* pubKey = subRecords.at(1)->castAs<pcpp::Asn1OctetStringRecord>();
            if (pubKey) {
                std::string pubKeyStr = pubKey->getValue();
                std::vector<uint8_t> pubKeyBytes(pubKeyStr.begin(), pubKeyStr.end());
                cert.public_key_hex = bytesToHex(pubKeyBytes);
            }
        }
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

std::string SSLParser::getSignatureAlgorithmName(const std::string& oid) {
    static const std::map<std::string, std::string> algorithms = {
        {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
        {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
        {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
        {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
        {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
        {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
        {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"}
    };
    
    auto it = algorithms.find(oid);
    return (it != algorithms.end()) ? it->second : oid;
}

std::string SSLParser::getKeyAlgorithmName(const std::string& oid) {
    static const std::map<std::string, std::string> algorithms = {
        {"1.2.840.113549.1.1.1", "rsaEncryption"},
        {"1.2.840.10045.2.1", "ecPublicKey"},
        {"1.2.840.10046.1.1", "dhPublicKey"}
    };
    
    auto it = algorithms.find(oid);
    return (it != algorithms.end()) ? it->second : oid;
}

std::string SSLParser::getAttributeName(const std::string& oid) {
    static const std::map<std::string, std::string> attributes = {
        {"2.5.4.3", "CN"},      // Common Name
        {"2.5.4.6", "C"},       // Country
        {"2.5.4.7", "L"},       // Locality
        {"2.5.4.8", "ST"},      // State
        {"2.5.4.10", "O"},      // Organization
        {"2.5.4.11", "OU"},     // Organizational Unit
        {"1.2.840.113549.1.9.1", "emailAddress"}
    };
    
    auto it = attributes.find(oid);
    return (it != attributes.end()) ? it->second : oid;
}

time_t SSLParser::parseUtcTime(const std::string& utcTimeStr) {
    // Parse UTC time string (format: YYMMDDHHMMSSZ)
    if (utcTimeStr.length() != 13) {
        return 0;
    }
    
    struct tm timeinfo = {};
    timeinfo.tm_year = std::stoi(utcTimeStr.substr(0, 2)) + 100; // Years since 1900
    timeinfo.tm_mon = std::stoi(utcTimeStr.substr(2, 2)) - 1;    // Months are 0-based
    timeinfo.tm_mday = std::stoi(utcTimeStr.substr(4, 2));
    timeinfo.tm_hour = std::stoi(utcTimeStr.substr(6, 2));
    timeinfo.tm_min = std::stoi(utcTimeStr.substr(8, 2));
    timeinfo.tm_sec = std::stoi(utcTimeStr.substr(10, 2));
    
    return mktime(&timeinfo);
}

void SSLParser::parseExtensions(pcpp::Asn1SequenceRecord* extensions, CertificateMetadata& cert) {
    if (!extensions) {
        return;
    }
    
    try {
        cert.has_extensions = true;
        // For now, just mark that extensions are present
        // Detailed extension parsing would require more specific ASN.1 record types
    } catch (const std::exception& e) {
        // Handle parsing errors gracefully
    }
}

std::string SSLParser::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

bool SSLParser::parseExtensions(pcpp::SSLHandshakeMessage* handshakeMsg, PacketMetadata& metadata) {
    if (!handshakeMsg) {
        return false;
    }
    
    // Check if this is a Client Hello or Server Hello message
    pcpp::SSLClientHelloMessage* clientHello = dynamic_cast<pcpp::SSLClientHelloMessage*>(handshakeMsg);
    pcpp::SSLServerHelloMessage* serverHello = dynamic_cast<pcpp::SSLServerHelloMessage*>(handshakeMsg);
    
    if (!clientHello && !serverHello) {
        return false;
    }
    
    int extCount = 0;
    if (clientHello) {
        extCount = clientHello->getExtensionCount();
    } else if (serverHello) {
        extCount = serverHello->getExtensionCount();
    }
    
    for (int i = 0; i < extCount; i++) {
        pcpp::SSLExtension* ext = nullptr;
        if (clientHello) {
            ext = clientHello->getExtension(i);
        } else if (serverHello) {
            ext = serverHello->getExtension(i);
        }
        
        if (!ext) continue;
        
        uint16_t extType = ext->getTypeAsInt();
        metadata.ssl.handshake_data.extension_types.push_back(extType);
        
        // Parse specific extension types
        switch (extType) {
            case 0x0000: { // Server Name Indication
                try {
                    pcpp::SSLServerNameIndicationExtension* sniExt = 
                        dynamic_cast<pcpp::SSLServerNameIndicationExtension*>(ext);
                    if (sniExt) {
                        std::string hostName = sniExt->getHostName();
                        if (!hostName.empty()) {
                            metadata.ssl.handshake_data.server_names.push_back(hostName);
                        }
                    }
                } catch (...) {
                    // If conversion fails, skip
                }
                break;
            }
            case 0x000A: { // Supported Groups
                try {
                    pcpp::TLSSupportedGroupsExtension* groupsExt = 
                        dynamic_cast<pcpp::TLSSupportedGroupsExtension*>(ext);
                    if (groupsExt) {
                        std::vector<uint16_t> groups = groupsExt->getSupportedGroups();
                        for (uint16_t group : groups) {
                            metadata.ssl.handshake_data.supported_groups.push_back(group);
                            metadata.ssl.handshake_data.supported_group_names.push_back(getSupportedGroupName(group));
                        }
                    }
                } catch (...) {
                    // If conversion fails, skip
                }
                break;
            }
            case 0x000B: { // EC Point Formats
                try {
                    pcpp::TLSECPointFormatExtension* ecExt = 
                        dynamic_cast<pcpp::TLSECPointFormatExtension*>(ext);
                    if (ecExt) {
                        std::vector<uint8_t> formats = ecExt->getECPointFormatList();
                        metadata.ssl.handshake_data.ec_point_formats.insert(
                            metadata.ssl.handshake_data.ec_point_formats.end(), 
                            formats.begin(), 
                            formats.end()
                        );
                    }
                } catch (...) {
                    // If conversion fails, skip
                }
                break;
            }
            case 0x002B: { // Supported Versions
                try {
                    pcpp::SSLSupportedVersionsExtension* versionsExt = 
                        dynamic_cast<pcpp::SSLSupportedVersionsExtension*>(ext);
                    if (versionsExt) {
                        std::vector<pcpp::SSLVersion> versions = versionsExt->getSupportedVersions();
                        for (pcpp::SSLVersion version : versions) {
                            metadata.ssl.handshake_data.supported_versions.push_back(version.asUInt());
                        }
                    }
                } catch (...) {
                    // If conversion fails, skip
                }
                break;
            }
        }
    }
    
    return true;
}

std::string SSLParser::getRecordTypeString(uint8_t recordType) {
    switch (recordType) {
        case pcpp::SSL_CHANGE_CIPHER_SPEC: return "Change Cipher Spec";
        case pcpp::SSL_ALERT: return "Alert";
        case pcpp::SSL_HANDSHAKE: return "Handshake";
        case pcpp::SSL_APPLICATION_DATA: return "Application Data";
        default: return "Unknown";
    }
}

std::string SSLParser::getHandshakeTypeString(uint8_t handshakeType) {
    switch (handshakeType) {
        case pcpp::SSL_CLIENT_HELLO: return "Client Hello";
        case pcpp::SSL_SERVER_HELLO: return "Server Hello";
        case pcpp::SSL_CERTIFICATE: return "Certificate";
        case pcpp::SSL_SERVER_KEY_EXCHANGE: return "Server Key Exchange";
        case pcpp::SSL_CERTIFICATE_REQUEST: return "Certificate Request";
        case pcpp::SSL_CERTIFICATE_VERIFY: return "Certificate Verify";
        case pcpp::SSL_CLIENT_KEY_EXCHANGE: return "Client Key Exchange";
        case pcpp::SSL_FINISHED: return "Finished";
        default: return "Unknown";
    }
}

std::string SSLParser::getVersionString(uint16_t version) {
    switch (version) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: return "Unknown";
    }
}

std::string SSLParser::getCipherSuiteName(uint16_t cipherSuiteId) {
    // Common cipher suite mapping
    static const std::map<uint16_t, std::string> cipherSuites = {
        {0x0004, "SSL_RSA_WITH_RC4_128_MD5"},
        {0x0005, "SSL_RSA_WITH_RC4_128_SHA"},
        {0x000A, "SSL_RSA_WITH_3DES_EDE_CBC_SHA"},
        {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
        {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
        {0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
        {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
        {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
        {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
        {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
        {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
        {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
        {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"}
    };
    
    auto it = cipherSuites.find(cipherSuiteId);
    if (it != cipherSuites.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << cipherSuiteId;
    return oss.str();
}

std::string SSLParser::getSupportedGroupName(uint16_t groupId) {
    // Common elliptic curve mapping
    static const std::map<uint16_t, std::string> groups = {
        {0x0017, "secp256r1"},
        {0x0018, "secp384r1"},
        {0x0019, "secp521r1"},
        {0x001D, "x25519"},
        {0x001E, "x448"},
        {0x0100, "FFDHE2048"},
        {0x0101, "FFDHE3072"},
        {0x0102, "FFDHE4096"},
        {0x0103, "FFDHE6144"},
        {0x0104, "FFDHE8192"}
    };
    
    auto it = groups.find(groupId);
    if (it != groups.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << groupId;
    return oss.str();
}

std::string SSLParser::bytesToHexString(const uint8_t* data, size_t length, size_t maxBytes) {
    if (!data || length == 0) {
        return "";
    }
    
    size_t showLength = (maxBytes > 0 && maxBytes < length) ? maxBytes : length;
    std::ostringstream oss;
    
    for (size_t i = 0; i < showLength; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i < showLength - 1) {
            oss << ":";
        }
    }
    
    if (maxBytes > 0 && length > maxBytes) {
        oss << "...";
    }
    
    return oss.str();
}

void SSLParser::formatForCSV(const SSLMetadata& ssl_meta, std::ostringstream& line, const std::string& separator) {
    line << ssl_meta.getRecordTypeString() << separator;
    line << ssl_meta.getVersionString() << separator;
    line << ssl_meta.getHandshakeTypeString() << separator;
    line << (ssl_meta.handshake_data.is_client_hello ? "Client Hello" : "") << separator;
    line << (ssl_meta.handshake_data.is_server_hello ? "Server Hello" : "") << separator;
    line << ssl_meta.getCipherSuitesString() << separator;
    line << ssl_meta.getExtensionsString() << separator;
    line << ssl_meta.getSupportedGroupsString() << separator;
    line << ssl_meta.getRandomDataString() << separator;
    line << ssl_meta.getSessionIDString() << separator;
    line << (ssl_meta.handshake_data.has_certificate ? "Yes" : "No") << separator;
    line << ssl_meta.handshake_data.certificate_count << separator;
    line << (ssl_meta.application_data_info.is_encrypted ? "Yes" : "No");
}

void SSLParser::formatForJSON(const SSLMetadata& ssl_meta, std::ostringstream& oss, 
                             std::function<std::string(const std::string&)> escapeJsonString) {
    oss << "\"ssl\":{";
    oss << "\"record_type\":\"" << escapeJsonString(ssl_meta.getRecordTypeString()) << "\",";
    oss << "\"version\":\"" << escapeJsonString(ssl_meta.getVersionString()) << "\",";
    oss << "\"handshake_type\":\"" << escapeJsonString(ssl_meta.getHandshakeTypeString()) << "\",";
    oss << "\"is_client_hello\":" << (ssl_meta.handshake_data.is_client_hello ? "true" : "false") << ",";
    oss << "\"is_server_hello\":" << (ssl_meta.handshake_data.is_server_hello ? "true" : "false") << ",";
    oss << "\"cipher_suites\":\"" << escapeJsonString(ssl_meta.getCipherSuitesString()) << "\",";
    oss << "\"extensions\":\"" << escapeJsonString(ssl_meta.getExtensionsString()) << "\",";
    oss << "\"supported_groups\":\"" << escapeJsonString(ssl_meta.getSupportedGroupsString()) << "\",";
    oss << "\"random_data\":\"" << escapeJsonString(ssl_meta.getRandomDataString()) << "\",";
    oss << "\"session_id\":\"" << escapeJsonString(ssl_meta.getSessionIDString()) << "\",";
    oss << "\"has_certificate\":" << (ssl_meta.handshake_data.has_certificate ? "true" : "false") << ",";
    oss << "\"certificate_count\":" << ssl_meta.handshake_data.certificate_count << ",";
    oss << "\"is_encrypted\":" << (ssl_meta.application_data_info.is_encrypted ? "true" : "false");
    oss << "}";
}

// New functions for manual SSL/TLS data parsing
bool SSLParser::parseManualSSL(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Get TCP layer
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer || tcpLayer->getLayerPayloadSize() == 0) {
        return false;
    }
    
    const uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payloadSize = tcpLayer->getLayerPayloadSize();
    
    // Check if there are enough bytes to parse SSL Record Layer
    if (payloadSize < 5) {
        return false;
    }
    
    // Parse SSL Record Layer
    uint8_t contentType = payload[0];
    uint16_t version = (payload[1] << 8) | payload[2];
    uint16_t length = (payload[3] << 8) | payload[4];
    
    // Validate SSL/TLS record format
    if (!isValidSSLRecord(contentType, version, length, payloadSize)) {
        return false;
    }
    
    // Set SSL metadata
    metadata.ssl.record_type = contentType;
    metadata.ssl.record_version = version;
    metadata.ssl.record_length = length;
    
    // Parse different record types based on Content Type
    switch (contentType) {
        case 0x16: // Handshake (22)
            return parseManualHandshake(payload + 5, length, metadata);
        case 0x14: // Change Cipher Spec (20)
            metadata.ssl.is_change_cipher_spec_layer = true;
            metadata.ssl.change_cipher_spec_data.is_change_cipher_spec = true;
            return true;
        case 0x15: // Alert (21)
            return parseManualAlert(payload + 5, length, metadata);
        case 0x17: // Application Data (23)
            metadata.ssl.is_application_data_layer = true;
            metadata.ssl.application_data_info.application_data_length = length;
            metadata.ssl.application_data_info.is_encrypted = true;
            return true;
        default:
            return false;
    }
}

bool SSLParser::isValidSSLRecord(uint8_t contentType, uint16_t version, uint16_t length, size_t payloadSize) {
    // Check if Content Type is valid
    if (contentType < 0x14 || contentType > 0x17) {
        return false;
    }
    
    // Check if version is valid
    if (version != 0x0300 && version != 0x0301 && version != 0x0302 && 
        version != 0x0303 && version != 0x0304) {
        return false;
    }
    
    // Check if length is reasonable
    if (length > payloadSize - 5 || length > 16384) { // SSL record maximum length 16KB
        return false;
    }
    
    return true;
}

bool SSLParser::parseManualHandshake(const uint8_t* handshakeData, uint16_t handshakeLength, PacketMetadata& metadata) {
    if (handshakeLength < 4) {
        return false;
    }
    
    // Parse Handshake message
    uint8_t handshakeType = handshakeData[0];
    uint32_t handshakeLengthField = (handshakeData[1] << 16) | (handshakeData[2] << 8) | handshakeData[3];
    
    metadata.ssl.is_handshake_layer = true;
    metadata.ssl.handshake_data.handshake_type = handshakeType;
    metadata.ssl.handshake_data.handshake_length = handshakeLengthField;
    
    // Parse based on Handshake type
    switch (handshakeType) {
        case 0x01: // Client Hello
            return parseManualClientHello(handshakeData + 4, handshakeLengthField, metadata);
        case 0x02: // Server Hello
            return parseManualServerHello(handshakeData + 4, handshakeLengthField, metadata);
        case 0x0B: // Certificate
            return parseManualCertificate(handshakeData + 4, handshakeLengthField, metadata);
        case 0x0E: // Server Key Exchange
        case 0x0F: // Certificate Request
        case 0x11: // Certificate Verify
        case 0x10: // Client Key Exchange
        case 0x14: // Finished
            // For other handshake types, only set basic information
            return true;
        default:
            return false;
    }
}

bool SSLParser::parseManualClientHello(const uint8_t* clientHelloData, uint32_t clientHelloLength, PacketMetadata& metadata) {
    if (clientHelloLength < 34) { // Minimum Client Hello length
        return false;
    }
    
    metadata.ssl.handshake_data.is_client_hello = true;
    
    // Parse Client Hello version (2 bytes)
    uint16_t clientVersion = (clientHelloData[0] << 8) | clientHelloData[1];
    metadata.ssl.handshake_data.handshake_version = clientVersion;
    
    // Parse Random (32 bytes)
    metadata.ssl.handshake_data.random_data.assign(clientHelloData + 2, clientHelloData + 34);
    
    size_t offset = 34;
    
    // Parse Session ID length (1 byte)
    if (offset >= clientHelloLength) return false;
    uint8_t sessionIdLength = clientHelloData[offset++];
    metadata.ssl.handshake_data.session_id_length = sessionIdLength;
    
    // Parse Session ID
    if (sessionIdLength > 0) {
        if (offset + sessionIdLength > clientHelloLength) return false;
        metadata.ssl.handshake_data.session_id.assign(clientHelloData + offset, clientHelloData + offset + sessionIdLength);
        offset += sessionIdLength;
    }
    
    // Parse Cipher Suites length (2 bytes)
    if (offset + 2 > clientHelloLength) return false;
    uint16_t cipherSuitesLength = (clientHelloData[offset] << 8) | clientHelloData[offset + 1];
    offset += 2;
    
    // Parse Cipher Suites
    if (offset + cipherSuitesLength > clientHelloLength) return false;
    metadata.ssl.handshake_data.cipher_suites.clear();
    for (size_t i = 0; i < cipherSuitesLength; i += 2) {
        if (offset + i + 1 < clientHelloLength) {
            uint16_t cipherSuite = (clientHelloData[offset + i] << 8) | clientHelloData[offset + i + 1];
            metadata.ssl.handshake_data.cipher_suites.push_back(cipherSuite);
        }
    }
    offset += cipherSuitesLength;
    
    // Parse Compression Methods length (1 byte)
    if (offset >= clientHelloLength) return false;
    uint8_t compressionMethodsLength = clientHelloData[offset++];
    
    // Parse Compression Methods
    if (offset + compressionMethodsLength > clientHelloLength) return false;
    metadata.ssl.handshake_data.compression_methods.clear();
    metadata.ssl.handshake_data.compression_methods_count = compressionMethodsLength;
    for (size_t i = 0; i < compressionMethodsLength; i++) {
        metadata.ssl.handshake_data.compression_methods.push_back(clientHelloData[offset + i]);
    }
    offset += compressionMethodsLength;
    
    // Parse Extensions (if present)
    if (offset + 2 <= clientHelloLength) {
        uint16_t extensionsLength = (clientHelloData[offset] << 8) | clientHelloData[offset + 1];
        offset += 2;
        
        if (offset + extensionsLength <= clientHelloLength) {
            parseManualExtensions(clientHelloData + offset, extensionsLength, metadata);
        }
    }
    
    return true;
}

bool SSLParser::parseManualServerHello(const uint8_t* serverHelloData, uint32_t serverHelloLength, PacketMetadata& metadata) {
    if (serverHelloLength < 34) { // Minimum Server Hello length
        return false;
    }
    
    metadata.ssl.handshake_data.is_server_hello = true;
    
    // Parse Server Hello version (2 bytes)
    uint16_t serverVersion = (serverHelloData[0] << 8) | serverHelloData[1];
    metadata.ssl.handshake_data.handshake_version = serverVersion;
    
    // Parse Random (32 bytes)
    metadata.ssl.handshake_data.random_data.assign(serverHelloData + 2, serverHelloData + 34);
    
    size_t offset = 34;
    
    // Parse Session ID length (1 byte)
    if (offset >= serverHelloLength) return false;
    uint8_t sessionIdLength = serverHelloData[offset++];
    metadata.ssl.handshake_data.session_id_length = sessionIdLength;
    
    // Parse Session ID
    if (sessionIdLength > 0) {
        if (offset + sessionIdLength > serverHelloLength) return false;
        metadata.ssl.handshake_data.session_id.assign(serverHelloData + offset, serverHelloData + offset + sessionIdLength);
        offset += sessionIdLength;
    }
    
    // Parse selected Cipher Suite (2 bytes)
    if (offset + 2 > serverHelloLength) return false;
    uint16_t selectedCipherSuite = (serverHelloData[offset] << 8) | serverHelloData[offset + 1];
    metadata.ssl.handshake_data.selected_cipher_suite_id = selectedCipherSuite;
    metadata.ssl.handshake_data.selected_cipher_suite = getCipherSuiteName(selectedCipherSuite);
    offset += 2;
    
    // Parse selected Compression Method (1 byte)
    if (offset >= serverHelloLength) return false;
    uint8_t selectedCompressionMethod = serverHelloData[offset++];
    metadata.ssl.handshake_data.compression_methods.clear();
    metadata.ssl.handshake_data.compression_methods.push_back(selectedCompressionMethod);
    metadata.ssl.handshake_data.compression_methods_count = 1;
    
    // Parse Extensions (if present)
    if (offset + 2 <= serverHelloLength) {
        uint16_t extensionsLength = (serverHelloData[offset] << 8) | serverHelloData[offset + 1];
        offset += 2;
        
        if (offset + extensionsLength <= serverHelloLength) {
            parseManualExtensions(serverHelloData + offset, extensionsLength, metadata);
        }
    }
    
    return true;
}

bool SSLParser::parseManualCertificate(const uint8_t* certData, uint32_t certLength, PacketMetadata& metadata) {
    if (certLength < 3) {
        return false;
    }
    
    metadata.ssl.handshake_data.has_certificate = true;
    
    // Parse certificate list length (3 bytes) - for validation
    uint32_t certListLength = (certData[0] << 16) | (certData[1] << 8) | certData[2];
    (void)certListLength; // Avoid unused variable warning
    
    size_t offset = 3;
    int certCount = 0;
    
    // Parse each certificate
    while (offset + 3 <= certLength && certCount < 10) { // Limit to maximum 10 certificates
        uint32_t certLength = (certData[offset] << 16) | (certData[offset + 1] << 8) | certData[offset + 2];
        offset += 3;
        
        if (offset + certLength > certLength) break;
        
        // Here we could further parse X.509 certificates, but for simplicity, we only record basic info
        std::string certInfo = "Certificate_" + std::to_string(certCount) + "_" + std::to_string(certLength);
        metadata.ssl.handshake_data.certificate_subjects.push_back(certInfo);
        
        offset += certLength;
        certCount++;
    }
    
    metadata.ssl.handshake_data.certificate_count = certCount;
    return true;
}

bool SSLParser::parseManualAlert(const uint8_t* alertData, uint16_t alertLength, PacketMetadata& metadata) {
    if (alertLength < 2) {
        return false;
    }
    
    metadata.ssl.is_alert_layer = true;
    metadata.ssl.alert_data.alert_level = alertData[0];
    metadata.ssl.alert_data.alert_description = alertData[1];
    
    return true;
}

void SSLParser::parseManualExtensions(const uint8_t* extData, uint16_t extLength, PacketMetadata& metadata) {
    size_t offset = 0;
    
    while (offset + 4 <= extLength) {
        // Parse Extension Type (2 bytes)
        uint16_t extType = (extData[offset] << 8) | extData[offset + 1];
        offset += 2;
        
        // Parse Extension Length (2 bytes)
        uint16_t extDataLength = (extData[offset] << 8) | extData[offset + 1];
        offset += 2;
        
        metadata.ssl.handshake_data.extension_types.push_back(extType);
        
        // Parse specific extension types
        if (extType == 0x0000 && extDataLength > 0) { // Server Name Indication
            parseManualSNI(extData + offset, extDataLength, metadata);
        }
        
        offset += extDataLength;
    }
}

void SSLParser::parseManualSNI(const uint8_t* sniData, uint16_t sniLength, PacketMetadata& metadata) {
    if (sniLength < 5) return;
    
    // SNI extension format: List Length(2) + Name Type(1) + Host Name Length(2) + Host Name
    uint16_t listLength = (sniData[0] << 8) | sniData[1];
    if (listLength < 3) return;
    
    uint8_t nameType = sniData[2];
    if (nameType != 0) return; // Only handle hostname type
    
    uint16_t hostNameLength = (sniData[3] << 8) | sniData[4];
    if (hostNameLength > sniLength - 5) return;
    
    std::string hostName(reinterpret_cast<const char*>(sniData + 5), hostNameLength);
    metadata.ssl.handshake_data.server_names.push_back(hostName);
}