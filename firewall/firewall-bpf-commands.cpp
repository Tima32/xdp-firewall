 #include <iostream>
 #include "ArgumentParser.hpp"
 #include "firewall-filters.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <string.h> // strerror

using namespace std;

extern bool GetDevice(ArgumentParser& ap);

void CommandAdd(ArgumentParser& ap)
{
	if (!GetDevice(ap))
		exit(-1);

	Filters::ParseArgs(ap);
	Filters::InitFiltersArray();

	int fd = bpf_obj_get("/sys/fs/bpf/enp4s0/xdp_config_map");
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file\n");
			exit(-1);
	}

	struct bpf_map_info info;
	__u32 info_len = sizeof(info);
	int err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
		if (err) {
			fprintf(stderr, "ERR: %s() can't get info - %s\n",
				__func__,  strerror(errno));
			exit(-1);
		}

	/* TODO: проверить информацию о карте, например. datarec ожидаемый размер */
	// map_expect.key_size    = sizeof(__u32);
	// map_expect.value_size  = sizeof(struct datarec);
	// map_expect.max_entries = XDP_ACTION_MAX;
	// err = check_map_fd_info(&info, &map_expect);
	// if (err) {
	// 	fprintf(stderr, "ERR: map via FD not compatible\n");
	// 	return err;

	struct Filter
	{
		uint8_t proto{0};

		uint32_t ip_src{0};
		uint32_t ip_dst{0};
	
		uint16_t port_src{0};
		uint16_t port_dst{0};
	};
	
	Filter value;
	for (size_t f = 0; f < Filters::filters.size(); f++)
	{
		// Find free space
		size_t pos;
		for (pos = 0; pos < 256; pos++)
		{
			if((bpf_map_lookup_elem(fd, &pos, &value))!= 0)
			{
				fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed pos:0x%X\n", pos);
				exit(-1);
			}
			
			if (value.proto == 0)
			{
				cout << "f: " << f << " pos: " << pos << endl;
				if ((bpf_map_update_elem(fd, &pos, &Filters::filters[f], BPF_ANY)) != 0) {
					fprintf(stderr,
						"ERR: bpf_map_lookup_elem failed pos:0x%X\n", pos);
					exit(-1);
				}
				break;
			}
		}
		if (pos == 256)
		{
			cout << "The filter array is full." << endl;
			exit(-1);
		}
	}
}