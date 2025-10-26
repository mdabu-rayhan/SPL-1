CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -pthread

SRC_DIR = src
INC_DIR = include

SRCS = $(SRC_DIR)/main.cpp \
       $(SRC_DIR)/packet_capture.cpp \
       $(SRC_DIR)/rule_engine.cpp \
       $(SRC_DIR)/ids.cpp \
       $(SRC_DIR)/blockchain.cpp \
       $(SRC_DIR)/logger.cpp \
       $(SRC_DIR)/stats.cpp

OBJS = $(SRCS:.cpp=.o)

TARGET = firewall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) -o $@ $^

clean:
	rm -f $(OBJS) $(TARGET)
