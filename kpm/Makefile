# KPM build. It does not use kernel vermagic, but compatibility still depends
# on KernelPatch ABI and the arm64 struct input_dev layout documented in the
# source. Treat unknown kernels as untested.
#
# Setup (once):
#   git clone https://github.com/bmax121/KernelPatch ../KernelPatch
#   # ARM bare-metal toolchain (NOT aarch64-linux-gnu):
#   # https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads
#
# Build:
#   make KP_DIR=/path/to/KernelPatch \
#        TARGET_COMPILE=/opt/arm-gnu-toolchain/bin/aarch64-none-elf-
#
# Output: hidhide.kpm -> push to device, load via KernelSU KPM page or:
#   ksud kpm load hidhide.kpm "vid=0x1234 pid=0x5678 name=goodix_ts"

KP_DIR         ?= ../KernelPatch
TARGET_COMPILE ?= aarch64-none-elf-

CC    := $(TARGET_COMPILE)gcc
STRIP := $(TARGET_COMPILE)strip

# -fno-PIC is mandatory (unsupported RELA relocation 311 otherwise)
CFLAGS := -O2 -Wall -Wextra -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector

CFLAGS += -fno-tree-loop-distribute-patterns

INCLUDE_DIRS  := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

all: hidhide.kpm

hidhide.kpm: hidhide_kpm.o
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^
	$(STRIP) --strip-unneeded $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

clean:
	rm -f *.o *.kpm

.PHONY: all clean
