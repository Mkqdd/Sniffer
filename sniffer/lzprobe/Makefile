CXX      := g++
CXXFLAGS := -std=c++17 -Wall -g \
            -I/root/Documents/pcapplusplus-25.05-ubuntu-22.04-gcc-11.4.0-x86_64/include \
            -I./include

LDFLAGS  := -L/root/Documents/pcapplusplus-25.05-ubuntu-22.04-gcc-11.4.0-x86_64/lib \
            -lPacket++ -lPcap++ -lCommon++ -lpcap -lpthread -lfftw3

SRC_DIRS := src src/utils src/parsers
BUILD_DIR := build

# main program source files
MAIN_SRCS := main.cpp $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.cpp))
MAIN_OBJS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(MAIN_SRCS))

TARGET := pcap_parser

all: $(TARGET)

$(TARGET): $(MAIN_OBJS)
	@echo "Linking $@ ..."
	$(CXX) -o $@ $^ $(LDFLAGS)



$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all clean