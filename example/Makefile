CLANG := clang
ARCH := __x86_64__
#ARCH := __aarch64__

CLANG_INCLUDE := -Iebpf_prog
CFLAGS := -D$(ARCH)

EBPF_SOURCE := ebpf_prog/bio-tracepoints.c \
			   ebpf_prog/ipcstat.c		   \
			   ebpf_prog/llcstat.c 		   \
			   ebpf_prog/cachestat.c 	   \
			   ebpf_prog/timers-raw-tracepoints.c

EBPF_BINARY := bio-tracepoints.elf		   \
			   ipcstat.elf				   \
			   llcstat.elf 				   \
			   cachestat.elf 			   \
			   timers-raw-tracepoints.elf

EBPF_SOURCE_DIR := ebpf_prog

all: $(EBPF_BINARY)

clean:
	rm -f $(EBPF_BINARY)

%.elf: $(EBPF_SOURCE_DIR)/%.c
	$(CLANG) $(CLANG_INCLUDE) $(CFLAGS) -O2 -target bpf -c $^  -o $@
