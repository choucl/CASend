CC := gcc

INC_DIR := inc
SRC_DIR := src
BUILD_DIR := build

HEADERS := $(wildcard $(INC_DIR)/*.h)
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

SERVER_TARGET := $(BUILD_DIR)/server
CLIENT_TARGET := $(BUILD_DIR)/client

__dir := $(shell mkdir -p $(BUILD_DIR))

DEBUG = -g
CFLAGS = -Wall -I$(INC_DIR) $(DEBUG)
LDFLAGS = -lpthread -lm

.PHONY: clean all

all: $(OBJECTS) $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(addprefix $(BUILD_DIR)/, server.o sock.o util.o)
	@echo [LINK] $@
	@$(CC) -o $@ $^ $(LDFLAGS)

$(CLIENT_TARGET): $(addprefix $(BUILD_DIR)/, client.o sock.o)
	@echo [LINK] $@
	@$(CC) -o $@ $^ $(LDFLAGS)

$(OBJECTS): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@echo [CXX] $< "-> .o"
	@$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf $(BUILD_DIR)
