#include <iostream>
#include "CaptureManager.h"
#include "PacketDispatcher.h"
#include "LoggerManager.h"
#include "utils/Config.h"

int main(int argc, char* argv[]) {
    Config config;

    // Parse command line arguments
    if (!config.parseArguments(argc, argv)) {
        config.printUsage(argv[0]);
        return 1;
    }

    // Handle help and version
    if (config.showHelp()) {
        config.printUsage(argv[0]);
        return 0;
    }

    if (config.showVersion()) {
        config.printVersion();
        return 0;
    }

    // Validate configuration
    if (!config.validate()) {
        config.printUsage(argv[0]);
        return 1;
    }

    // Display configuration if verbose
    if (config.isVerbose()) {
        std::cout << "Configuration:\n"
                  << "  Input file: " << config.getInputFile() << "\n"
                  << "  Output directory: " << config.getOutputDir() << "\n";
        if (!config.getFilter().empty()) {
            std::cout << "  BPF filter: " << config.getFilter() << "\n";
        }
        if (!config.getProtocolFilter().empty()) {
            std::cout << "  Protocol filter: " << config.getProtocolFilter() << "\n";
        }
        if (config.getMaxPackets() > 0) {
            std::cout << "  Max packets: " << config.getMaxPackets() << "\n";
        }
        std::cout << "  JSON output: " << (config.isJsonOutput() ? "enabled" : "disabled") << "\n"
                  << "  Statistics: " << (config.showStatistics() ? "enabled" : "disabled") << "\n\n";
    }

    try {
        // Initialize components with custom output directory
        LoggerManager logger(config.getOutputDir());
        
        // Set output directory based on input file name
        logger.setOutputDirectoryFromFile(config.getInputFile(), config.getOutputDir());
        
        // Set output format based on configuration
        if (config.isJsonOutput()) {
            logger.setOutputFormat(true);
        }
        
        PacketDispatcher dispatcher(logger);
        CaptureManager manager(config.getInputFile(), dispatcher);

        // Apply configuration to manager if supported
        // TODO: Add support for filters, max_packets, etc. in CaptureManager

        if (!config.isQuiet()) {
            std::cout << "Starting packet analysis...\n";
        }

        // Run the analysis
        manager.run();
        
        // Force flush all remaining connections at the end of processing
        logger.forceFlushAllConnections();
        
        if (!config.isQuiet()) {
            std::cout << "Packet analysis completed successfully.\n";
        }

        // TODO: Add statistics output if enabled
        if (config.showStatistics()) {
            std::cout << "\nStatistics:\n";
            std::cout << "  Total packets processed: [TODO: implement]\n";
            std::cout << "  Protocols detected: [TODO: implement]\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}