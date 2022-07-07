LIBBPF_DIR := ./libbpf/src/

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a




(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi




all: llvm-check $(LIBBPF_DIR)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
