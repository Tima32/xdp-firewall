LLC ?= llc
CLANG ?= clang
CC ?= gcc

LIBBPF_DIR := ./libbpf/src/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

XDP_TARGETS  := kern/xdp_prog_kern
XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

EXTRA_DEPS += $(COMMON_DIR)/xdp_stats_kern.h $(COMMON_DIR)/xdp_stats_kern_user.h

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/


all: llvm-check $(LIBBPF_DIR) $(XDP_OBJ)

.PHONY: clean $(CLANG) $(LLC)


llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

$(XDP_OBJ): %.o: %.c $(OBJECT_LIBBPF)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -f $(XDP_OBJ)
