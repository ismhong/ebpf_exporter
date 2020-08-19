CLANG := clang
ARCH := __x86_64__
#ARCH := __aarch64__

CLANG_INCLUDE :=
CFLAGS := -D$(ARCH)

EBPF_BINARY := bio-tracepoints.elf           \
               ipcstat.elf                   \
               llcstat.elf                   \
               cachestat.elf                 \
               cachestat-complex.elf         \
               runqlat.elf                   \
               timers-raw-tracepoints.elf

EBPF_SOURCE_DIR := ebpf_prog

all: $(EBPF_BINARY)

clean:
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): %.elf:$(EBPF_SOURCE_DIR)/%.c
	$(CLANG) $(CLANG_INCLUDE) $(CFLAGS) -O2 -target bpf -c $^  -o $@
