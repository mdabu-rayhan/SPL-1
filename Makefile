CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

SRC = src/main.cpp src/capture.cpp src/rules.cpp src/firewall.cpp src/ids.cpp src/logger.cpp src/util.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = firewall_sim

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)

clean:
	rm -f $(OBJ) $(TARGET)
