# Minimal Makefile for main.cpp + packet_capture_manual_decoding.cpp
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g3 -Iinclude -pthread
LDFLAGS = -lpcap

SRCDIR = src
BINDIR = src/output
TARGET = $(BINDIR)/main

SRCS = $(SRCDIR)/main.cpp $(SRCDIR)/packet_capture_manual_decoding.cpp $(SRCDIR)/firewall.cpp $(SRCDIR)/stats.cpp $(SRCDIR)/ids.cpp
OBJS = $(SRCS:.cpp=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BINDIR):
	mkdir -p $(BINDIR)

run: all
	sudo ./$(TARGET)

clean:
	rm -f $(SRCDIR)/*.o $(TARGET)
