# Compiler
CC = gcc

# Compiler flags
CFLAGS = -maes -msse4 -I/usr/include/openssl

# Linker flags
LDFLAGS = -lssl -lcrypto

# Source files
ASSEMBLY_SRCS = $(wildcard *.s)
C_SRCS = ecb_main.c aes.c

# Object files
ASSEMBLY_OBJS = $(ASSEMBLY_SRCS:.s=.o)
C_OBJS = ecb_main.o aes.o

# Executable
TARGET = ecb_exe

# Default rule
all: $(TARGET)

# Rule to compile assembly files
$(ASSEMBLY_OBJS): %.o : %.s
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to link and build the final executable
$(TARGET): $(ASSEMBLY_OBJS) $(C_OBJS)
	$(CC) $(CFLAGS) $(C_SRCS) $(ASSEMBLY_OBJS) $(LDFLAGS) -o $(TARGET)

# Clean up object files and the executable
clean:
	rm -f $(ASSEMBLY_OBJS) $(C_OBJS) $(TARGET)