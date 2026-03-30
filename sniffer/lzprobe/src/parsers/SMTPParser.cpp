#include "parsers/SMTPParser.h"
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/SmtpLayer.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

bool SMTPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    // Check if this is SMTP traffic (ports 25, 465, or 587)
    if (!isSMTPPacket(packet)) {
        return false;
    }

    // Set SMTP presence flag
    metadata.has_smtp = true;

    // Try to get SMTP request layer first
    auto* smtpRequestLayer = packet.getLayerOfType<pcpp::SmtpRequestLayer>();
    if (smtpRequestLayer) {
        metadata.smtp.is_request = true;
        metadata.smtp.type = "REQUEST";
        return parseRequest(smtpRequestLayer, metadata);
    }

    // Try to get SMTP response layer
    auto* smtpResponseLayer = packet.getLayerOfType<pcpp::SmtpResponseLayer>();
    if (smtpResponseLayer) {
        metadata.smtp.is_response = true;
        metadata.smtp.type = "RESPONSE";
        return parseResponse(smtpResponseLayer, metadata);
    }

    // If no specific SMTP layer found, still mark as SMTP but with minimal info
    metadata.smtp.message_length = tcpLayer->getLayerPayloadSize();
    if (metadata.smtp.message_length > 0) {
        metadata.smtp.message_preview = extractMessagePreview(
            tcpLayer->getLayerPayload(), 
            metadata.smtp.message_length
        );
    }

    return true;
}

bool SMTPParser::isSMTPPacket(pcpp::Packet& packet) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    uint16_t srcPort = tcpLayer->getSrcPort();
    uint16_t dstPort = tcpLayer->getDstPort();

    // Check for SMTP ports: 25 (standard), 465 (SMTPS), 587 (submission)
    return (srcPort == 25 || dstPort == 25 || 
            srcPort == 465 || dstPort == 465 || 
            srcPort == 587 || dstPort == 587);
}

bool SMTPParser::parseRequest(pcpp::SmtpRequestLayer* smtpLayer, PacketMetadata& metadata) {
    if (!smtpLayer) {
        return false;
    }

    // Get command
    auto command = smtpLayer->getCommand();
    metadata.smtp.command = commandToString(command);

    // Get command options/arguments
    std::string options = smtpLayer->getCommandOption(true);
    if (!options.empty()) {
        metadata.smtp.arguments = options;
    }

    // Get message length and preview
    metadata.smtp.message_length = smtpLayer->getHeaderLen();
    if (metadata.smtp.message_length > 0) {
        metadata.smtp.message_preview = extractMessagePreview(
            smtpLayer->getData(), 
            metadata.smtp.message_length
        );
    }

    return true;
}

bool SMTPParser::parseResponse(pcpp::SmtpResponseLayer* smtpLayer, PacketMetadata& metadata) {
    if (!smtpLayer) {
        return false;
    }

    // Get status code
    auto statusCode = smtpLayer->getStatusCode();
    metadata.smtp.status_code = static_cast<uint16_t>(statusCode);

    // Get status options/text
    std::string statusText = smtpLayer->getStatusOption(true);
    if (!statusText.empty()) {
        metadata.smtp.status_text = statusText;
    }

    // Get message length and preview
    metadata.smtp.message_length = smtpLayer->getHeaderLen();
    if (metadata.smtp.message_length > 0) {
        metadata.smtp.message_preview = extractMessagePreview(
            smtpLayer->getData(), 
            metadata.smtp.message_length
        );
    }

    return true;
}

std::string SMTPParser::extractMessagePreview(const uint8_t* data, size_t dataLen, size_t maxPreviewLen) {
    if (!data || dataLen == 0) {
        return "";
    }

    size_t previewLen = std::min(dataLen, maxPreviewLen);
    std::string preview;
    preview.reserve(previewLen);

    for (size_t i = 0; i < previewLen; ++i) {
        uint8_t byte = data[i];
        if (byte >= 32 && byte <= 126) {
            // Printable ASCII
            preview += static_cast<char>(byte);
        } else if (byte == '\n') {
            preview += "\\n";
        } else if (byte == '\r') {
            preview += "\\r";
        } else if (byte == '\t') {
            preview += "\\t";
        } else {
            // Non-printable, show as hex
            preview += "\\x" + std::to_string(byte);
        }
    }

    return cleanMessagePreview(preview);
}

std::string SMTPParser::cleanMessagePreview(const std::string& preview) {
    std::string cleaned = preview;
    
    // Remove excessive whitespace
    std::regex excessive_whitespace("\\s{3,}");
    cleaned = std::regex_replace(cleaned, excessive_whitespace, " ... ");
    
    // Truncate if too long
    if (cleaned.length() > 200) {
        cleaned = cleaned.substr(0, 197) + "...";
    }
    
    return cleaned;
}

std::string SMTPParser::commandToString(pcpp::SmtpRequestLayer::SmtpCommand command) {
    switch (command) {
        case pcpp::SmtpRequestLayer::SmtpCommand::HELO:
            return "HELO";
        case pcpp::SmtpRequestLayer::SmtpCommand::EHLO:
            return "EHLO";
        case pcpp::SmtpRequestLayer::SmtpCommand::MAIL:
            return "MAIL";
        case pcpp::SmtpRequestLayer::SmtpCommand::RCPT:
            return "RCPT";
        case pcpp::SmtpRequestLayer::SmtpCommand::DATA:
            return "DATA";
        case pcpp::SmtpRequestLayer::SmtpCommand::QUIT:
            return "QUIT";
        case pcpp::SmtpRequestLayer::SmtpCommand::RSET:
            return "RSET";
        case pcpp::SmtpRequestLayer::SmtpCommand::VRFY:
            return "VRFY";
        case pcpp::SmtpRequestLayer::SmtpCommand::EXPN:
            return "EXPN";
        case pcpp::SmtpRequestLayer::SmtpCommand::HELP:
            return "HELP";
        case pcpp::SmtpRequestLayer::SmtpCommand::NOOP:
            return "NOOP";
        case pcpp::SmtpRequestLayer::SmtpCommand::TURN:
            return "TURN";
        case pcpp::SmtpRequestLayer::SmtpCommand::AUTH:
            return "AUTH";
        case pcpp::SmtpRequestLayer::SmtpCommand::STARTTLS:
            return "STARTTLS";
        case pcpp::SmtpRequestLayer::SmtpCommand::SEND:
            return "SEND";
        case pcpp::SmtpRequestLayer::SmtpCommand::SOML:
            return "SOML";
        case pcpp::SmtpRequestLayer::SmtpCommand::SAML:
            return "SAML";
        case pcpp::SmtpRequestLayer::SmtpCommand::ATRN:
            return "ATRN";
        case pcpp::SmtpRequestLayer::SmtpCommand::BDAT:
            return "BDAT";
        case pcpp::SmtpRequestLayer::SmtpCommand::ETRN:
            return "ETRN";
        case pcpp::SmtpRequestLayer::SmtpCommand::XADR:
            return "XADR";
        case pcpp::SmtpRequestLayer::SmtpCommand::XCIR:
            return "XCIR";
        case pcpp::SmtpRequestLayer::SmtpCommand::XSTA:
            return "XSTA";
        case pcpp::SmtpRequestLayer::SmtpCommand::XGEN:
            return "XGEN";
        case pcpp::SmtpRequestLayer::SmtpCommand::UNK:
        default:
            return "UNKNOWN";
    }
}

std::string SMTPParser::statusCodeToString(pcpp::SmtpResponseLayer::SmtpStatusCode statusCode) {
    return std::to_string(static_cast<int>(statusCode));
}

std::string SMTPParser::dataToString(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen == 0) {
        return "";
    }

    std::string result;
    result.reserve(dataLen);

    for (size_t i = 0; i < dataLen; ++i) {
        uint8_t byte = data[i];
        // Only include printable characters and common whitespace
        if ((byte >= 32 && byte <= 126) || byte == '\r' || byte == '\n' || byte == '\t') {
            result += static_cast<char>(byte);
        } else {
            // Stop at first non-text character (likely binary data)
            break;
        }
    }

    return result;
}
