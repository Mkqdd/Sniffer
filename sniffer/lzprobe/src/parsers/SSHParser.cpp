#include "parsers/SSHParser.h"
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/SSHLayer.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

bool SSHParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    // Check if this is SSH traffic (port 22)
    if (!isSSHPacket(packet)) {
        return false;
    }

    // Set SSH presence flag
    metadata.has_ssh = true;

    // Try to get SSH layer using PcapPlusPlus
    auto* sshLayer = packet.getLayerOfType<pcpp::SSHLayer>();
    if (!sshLayer) {
        // If no SSH layer found, still mark as SSH but with minimal info
        metadata.ssh.is_encrypted = true;
        metadata.ssh.message_type = "ENCRYPTED";
        metadata.ssh.total_message_length = tcpLayer->getLayerPayloadSize();
        if (metadata.ssh.total_message_length > 0) {
            metadata.ssh.message_preview = extractMessagePreview(
                tcpLayer->getLayerPayload(), 
                metadata.ssh.total_message_length
            );
        }
        return true;
    }

    // Parse different types of SSH messages
    auto* identificationLayer = dynamic_cast<pcpp::SSHIdentificationMessage*>(sshLayer);
    if (identificationLayer) {
        metadata.ssh.is_identification = true;
        metadata.ssh.message_type = "IDENTIFICATION";
        return parseIdentification(identificationLayer, metadata);
    }

    auto* keyExchangeLayer = dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(sshLayer);
    if (keyExchangeLayer) {
        metadata.ssh.is_key_exchange = true;
        metadata.ssh.message_type = "KEY_EXCHANGE";
        return parseKeyExchange(keyExchangeLayer, metadata);
    }

    auto* handshakeLayer = dynamic_cast<pcpp::SSHHandshakeMessage*>(sshLayer);
    if (handshakeLayer) {
        metadata.ssh.is_handshake = true;
        metadata.ssh.message_type = "HANDSHAKE";
        return parseHandshake(handshakeLayer, metadata);
    }

    auto* encryptedLayer = dynamic_cast<pcpp::SSHEncryptedMessage*>(sshLayer);
    if (encryptedLayer) {
        metadata.ssh.is_encrypted = true;
        metadata.ssh.message_type = "ENCRYPTED";
        return parseEncrypted(encryptedLayer, metadata);
    }

    // If we can't determine the type, mark as encrypted
    metadata.ssh.is_encrypted = true;
    metadata.ssh.message_type = "ENCRYPTED";
    metadata.ssh.total_message_length = sshLayer->getHeaderLen();
    if (metadata.ssh.total_message_length > 0) {
        metadata.ssh.message_preview = extractMessagePreview(
            sshLayer->getData(), 
            metadata.ssh.total_message_length
        );
    }

    return true;
}

bool SSHParser::isSSHPacket(pcpp::Packet& packet) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    uint16_t srcPort = tcpLayer->getSrcPort();
    uint16_t dstPort = tcpLayer->getDstPort();

    // Check for SSH port 22
    return (srcPort == 22 || dstPort == 22);
}

bool SSHParser::parseIdentification(pcpp::SSHIdentificationMessage* sshLayer, PacketMetadata& metadata) {
    if (!sshLayer) {
        return false;
    }

    // Get identification message
    std::string identification = sshLayer->getIdentificationMessage();
    metadata.ssh.identification_string = identification;
    
    // Extract software version and protocol version
    metadata.ssh.software_version = extractSoftwareVersion(identification);
    metadata.ssh.protocol_version = extractProtocolVersion(identification);
    
    // Set message length and preview
    metadata.ssh.total_message_length = sshLayer->getHeaderLen();
    metadata.ssh.message_preview = cleanMessagePreview(identification);
    
    // Set session info
    metadata.ssh.session_info = metadata.ssh.getSessionInfo();
    
    return true;
}

bool SSHParser::parseHandshake(pcpp::SSHHandshakeMessage* sshLayer, PacketMetadata& metadata) {
    if (!sshLayer) {
        return false;
    }

    // Get handshake message details
    metadata.ssh.handshake_message_type = sshLayer->getMessageType();
    metadata.ssh.handshake_type_str = sshLayer->getMessageTypeStr();
    metadata.ssh.packet_length = sshLayer->getHeaderLen();
    metadata.ssh.padding_length = sshLayer->getPaddingLength();
    metadata.ssh.message_content_length = sshLayer->getSSHHandshakeMessageLength();
    
    // Get message content preview
    uint8_t* messageContent = sshLayer->getSSHHandshakeMessage();
    if (messageContent && metadata.ssh.message_content_length > 0) {
        metadata.ssh.message_preview = extractMessagePreview(
            messageContent, 
            metadata.ssh.message_content_length
        );
    }
    
    // Set total message length
    metadata.ssh.total_message_length = sshLayer->getHeaderLen();
    
    // Set session info
    metadata.ssh.session_info = metadata.ssh.getSessionInfo();
    
    return true;
}

bool SSHParser::parseKeyExchange(pcpp::SSHKeyExchangeInitMessage* sshLayer, PacketMetadata& metadata) {
    if (!sshLayer) {
        return false;
    }

    // First parse as handshake message
    if (!parseHandshake(sshLayer, metadata)) {
        return false;
    }

    // Get key exchange specific fields
    metadata.ssh.cookie_hex = sshLayer->getCookieAsHexStream();
    metadata.ssh.key_exchange_algorithms = sshLayer->getKeyExchangeAlgorithms();
    metadata.ssh.server_host_key_algorithms = sshLayer->getServerHostKeyAlgorithms();
    metadata.ssh.encryption_algorithms_client_to_server = sshLayer->getEncryptionAlgorithmsClientToServer();
    metadata.ssh.encryption_algorithms_server_to_client = sshLayer->getEncryptionAlgorithmsServerToClient();
    metadata.ssh.mac_algorithms_client_to_server = sshLayer->getMacAlgorithmsClientToServer();
    metadata.ssh.mac_algorithms_server_to_client = sshLayer->getMacAlgorithmsServerToClient();
    metadata.ssh.compression_algorithms_client_to_server = sshLayer->getCompressionAlgorithmsClientToServer();
    metadata.ssh.compression_algorithms_server_to_client = sshLayer->getCompressionAlgorithmsServerToClient();
    metadata.ssh.languages_client_to_server = sshLayer->getLanguagesClientToServer();
    metadata.ssh.languages_server_to_client = sshLayer->getLanguagesServerToClient();
    metadata.ssh.first_kex_packet_follows = sshLayer->isFirstKexPacketFollows();
    
    // Update session info
    metadata.ssh.session_info = metadata.ssh.getSessionInfo();
    
    return true;
}

bool SSHParser::parseEncrypted(pcpp::SSHEncryptedMessage* sshLayer, PacketMetadata& metadata) {
    if (!sshLayer) {
        return false;
    }

    // For encrypted messages, we can only extract basic information
    metadata.ssh.total_message_length = sshLayer->getHeaderLen();
    metadata.ssh.message_preview = "[ENCRYPTED SSH DATA]";
    metadata.ssh.session_info = metadata.ssh.getSessionInfo();
    
    return true;
}

std::string SSHParser::extractSoftwareVersion(const std::string& identification) {
    // SSH identification format: "SSH-2.0-OpenSSH_8.9"
    std::regex sshPattern(R"(SSH-(\d+\.\d+)-(.+))");
    std::smatch match;
    
    if (std::regex_search(identification, match, sshPattern) && match.size() >= 3) {
        return match[2].str();
    }
    
    return "";
}

std::string SSHParser::extractProtocolVersion(const std::string& identification) {
    // SSH identification format: "SSH-2.0-OpenSSH_8.9"
    std::regex sshPattern(R"(SSH-(\d+\.\d+)-(.+))");
    std::smatch match;
    
    if (std::regex_search(identification, match, sshPattern) && match.size() >= 2) {
        return match[1].str();
    }
    
    return "";
}

std::string SSHParser::handshakeMessageTypeToString(uint8_t messageType) {
    switch (messageType) {
        case 20: return "SSH_MSG_KEX_INIT";
        case 21: return "SSH_MSG_NEW_KEYS";
        case 30: return "SSH_MSG_KEX_DH_INIT";
        case 31: return "SSH_MSG_KEX_DH_REPLY";
        case 32: return "SSH_MSG_KEX_DH_GEX_INIT";
        case 33: return "SSH_MSG_KEX_DH_GEX_REPLY";
        case 34: return "SSH_MSG_KEX_DH_GEX_REQUEST";
        default: return "SSH_MSG_UNKNOWN";
    }
}

std::string SSHParser::extractMessagePreview(const uint8_t* data, size_t dataLen, size_t maxPreviewLen) {
    if (!data || dataLen == 0) {
        return "";
    }
    
    size_t previewLen = std::min(dataLen, maxPreviewLen);
    std::string preview(dataToString(data, previewLen));
    
    // Clean the preview
    return cleanMessagePreview(preview);
}

std::string SSHParser::cleanMessagePreview(const std::string& preview) {
    if (preview.empty()) {
        return "";
    }
    
    std::string cleaned = preview;
    
    // Remove or replace control characters
    std::replace_if(cleaned.begin(), cleaned.end(), 
        [](char c) { return !std::isprint(c) && c != '\n' && c != '\r' && c != '\t'; }, 
        '.');
    
    // Limit length if too long
    if (cleaned.length() > 100) {
        cleaned = cleaned.substr(0, 97) + "...";
    }
    
    return cleaned;
}

std::string SSHParser::dataToString(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen == 0) {
        return "";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < dataLen; ++i) {
        if (std::isprint(data[i]) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            oss << static_cast<char>(data[i]);
        } else {
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
    }
    
    return oss.str();
}
