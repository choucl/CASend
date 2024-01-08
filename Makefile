CC := gcc

INC_DIR := inc
SRC_DIR := src
BUILD_DIR := build

HEADERS := $(wildcard $(INC_DIR)/*.h)
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

SERVER_TARGET := $(BUILD_DIR)/server
SENDER_TARGET := $(BUILD_DIR)/sender
RECEIVER_TARGET := $(BUILD_DIR)/receiver

__dir := $(shell mkdir -p $(BUILD_DIR))

DEBUG = -g -DQUIET=0 -DDEBUG
CFLAGS = -Wall -I$(INC_DIR) $(DEBUG)
LDFLAGS = -lpthread -lm -lcrypto

.PHONY: clean all

all: $(OBJECTS) $(SERVER_TARGET) $(SENDER_TARGET) $(RECEIVER_TARGET)

$(SERVER_TARGET): $(addprefix $(BUILD_DIR)/, server.o sock.o packet.o util.o rsa.o)
	@echo [LINK] $@
	@$(CC) -o $@ $^ $(LDFLAGS)

$(SENDER_TARGET): $(addprefix $(BUILD_DIR)/, sender.o sock.o packet.o util.o rsa.o)
	@echo [LINK] $@
	@$(CC) -o $@ $^ $(LDFLAGS)

$(RECEIVER_TARGET): $(addprefix $(BUILD_DIR)/, receiver.o sock.o packet.o util.o rsa.o)
	@echo [LINK] $@
	@$(CC) -o $@ $^ $(LDFLAGS)

$(OBJECTS): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@echo [CXX] $< "-> .o"
	@$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf $(BUILD_DIR)
