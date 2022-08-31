#include <arpa/inet.h> 
 
#include <iostream>
#include "ArgumentParser.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <string.h> // strerror
#include <linux/in.h>
#include <limits.h>

using namespace std;

struct Filter
{
    uint8_t proto{ 0 };

    uint32_t ip_src_begin{ 0 };
    uint32_t ip_src_end{ 0 };
    uint32_t ip_dst_begin{ 0 };
    uint32_t ip_dst_end{ 0 };
	
    uint16_t port_src_begin{ 0 };
    uint16_t port_src_end{ 0 };
    uint16_t port_dst_begin{ 0 };
    uint16_t port_dst_end{ 0 };
};
extern bool GetDevice(ArgumentParser& ap);

static uint8_t ParseProto(const string& proto)
{
	uint8_t proto_num{0};

	if (proto == "icmp")
		proto_num = IPPROTO_ICMP;
	else if (proto == "tcp")
		proto_num = IPPROTO_TCP;
	else if (proto == "udp")
		proto_num = IPPROTO_UDP;

	return proto_num;
}
static string ToIP(uint32_t ipi)
{
	uint8_t* bytes = (uint8_t*)&ipi;

	stringstream ss;
	ss << uint16_t(bytes[0]) << "." << uint16_t(bytes[1]) << "." << uint16_t(bytes[2]) << "." << uint16_t(bytes[3]);
	return ss.str();
}

void CommandAdd(ArgumentParser& ap)
{
	if (ap.size() < 3)
	{
		cout << "Error: The network device name was not specified." << endl;
		exit(-1);
	}
	auto dev = ap[2];


	// Arguments
	uint8_t proto{0xFF};
	uint32_t ip_src{0};
	uint32_t ip_dst{0};
	uint16_t port_src{0};
	uint16_t port_dst{0};


	// Parsing arguments
	try
	{
		auto str_prot = ap.get<string>("--proto");
		proto = ParseProto(str_prot);
		if (proto == 0)
		{
			cout << "Error: Protocol " << str_prot << " is not supportet." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}

	try
	{
		auto str_ip = ap.get<string>("--ip-src");
		ip_src = inet_addr(str_ip.c_str());
		if (ip_src == INADDR_NONE)
		{
			cout << "Error: Ip address " << str_ip << " is not correct." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}
	try
	{
		auto str_ip = ap.get<string>("--ip-dst");
		ip_dst = inet_addr(str_ip.c_str());
		if (ip_dst == INADDR_NONE)
		{
			cout << "Error: Ip address " << str_ip << " is not correct." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}

	try
	{
		port_src = ap.get<uint16_t>("--port-src");
		port_src = ntohs(port_src);
	}
	catch(...)
	{}
	try
	{
		port_dst = ap.get<uint16_t>("--port-dst");
		port_dst = ntohs(port_dst);
	}
	catch(...)
	{}
	

	// Filter
	Filter filter;

	filter.proto = proto;

	filter.ip_src_begin = ip_src;
	if (ip_src == 0)
		filter.ip_src_end = 0xFFFFFFFF;
	else
		filter.ip_src_end = ip_src;

	filter.ip_dst_begin = ip_dst;
	if (ip_dst == 0)
		filter.ip_dst_end = 0xFFFFFFFF;
	else
		filter.ip_dst_end = ip_dst;

	filter.port_src_begin = port_src;
	if (port_src == 0)
		filter.port_src_end = 0xFFFF;
	else
		filter.port_src_end = port_src;

	filter.port_dst_begin = port_dst;
	if (port_dst == 0)
		filter.port_dst_end = 0xFFFF;
	else
		filter.port_dst_end = port_dst;

	cout << "Info:" << endl;
	cout << "Proto id: " << (uint32_t)filter.proto << endl;
	cout << "ip s b: " << ToIP(filter.ip_src_begin) << endl;
	cout << "ip s e: " << ToIP(filter.ip_src_end) << endl;
	cout << "ip d b: " << ToIP(filter.ip_dst_begin) << endl;
	cout << "ip d e: " << ToIP(filter.ip_dst_end) << endl;
	cout << "port s b: " << ntohs(filter.port_src_begin) << endl;
	cout << "port s e: " << ntohs(filter.port_src_end) << endl;
	cout << "port d b: " << ntohs(filter.port_dst_begin) << endl;
	cout << "port d e: " << ntohs(filter.port_dst_end) << endl;
		

	// Open array
	string path_to_file;
	path_to_file.resize(PATH_MAX, '\0');
	std::snprintf(path_to_file.data(), PATH_MAX, "/sys/fs/bpf/%s/xdp_config_map", dev.c_str());
	int fd = bpf_obj_get(path_to_file.c_str());
	if (fd < 0) {
		fprintf(stderr,
			"ERROR: Failed to open bpf map file.\n");
			exit(-1);
	}
	
	// Find free space
	size_t pos;
	Filter value;
	for (pos = 0; pos < 256; pos++)
	{
		if((bpf_map_lookup_elem(fd, &pos, &value)) != 0)
		{
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed pos:0x%X\n", pos);
			exit(-1);
		}
			
		if (value.proto == 0)
		{
			cout << "pos: " << pos << endl;
			if ((bpf_map_update_elem(fd, &pos, &filter, BPF_ANY)) != 0) {
				fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed pos:0x%I64u\n", pos);
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
void CommandDiap(ArgumentParser& ap)
{
	if (ap.size() < 3)
	{
		cout << "Error: The network device name was not specified." << endl;
		exit(-1);
	}
	auto dev = ap[2];


	// Arguments
	uint8_t proto{0xFF};
	uint32_t ip_src_begin{0};
	uint32_t ip_src_end{0xFFFFFFFF};
	uint32_t ip_dst_begin{0};
	uint32_t ip_dst_end{0xFFFFFFFF};
	uint16_t port_src_begin{0};
	uint16_t port_src_end{0xFFFF};
	uint16_t port_dst_begin{0};
	uint16_t port_dst_end{0xFFFF};


	// Parsing arguments
	try
	{
		auto str_prot = ap.get<string>("--proto");
		proto = ParseProto(str_prot);
		if (proto == 0)
		{
			cout << "Error: Protocol " << str_prot << " is not supportet." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}

	// Src
	try
	{
		auto str_ip = ap.get<string>("--ip-src-begin");
		ip_src_begin = inet_addr(str_ip.c_str());
		if (ip_src_begin == INADDR_NONE)
		{
			cout << "Error: Ip address " << str_ip << " is not correct." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}
	try
	{
		auto str_ip = ap.get<string>("--ip-src-end");
		ip_src_end = inet_addr(str_ip.c_str());
		if (ip_src_end == INADDR_NONE)
		{
			cout << "Error: Ip address " << str_ip << " is not correct." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}

	// Dst
	try
	{
		auto str_ip = ap.get<string>("--ip-dst-begin");
		ip_dst_begin = inet_addr(str_ip.c_str());
		if (ip_dst_begin == INADDR_NONE)
		{
			cout << "Error: Ip address " << str_ip << " is not correct." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}
	try
	{
		auto str_ip = ap.get<string>("--ip-dst-end");
		ip_dst_end = inet_addr(str_ip.c_str());
		if (ip_dst_end == INADDR_NONE)
		{
			cout << "Error: Ip address " << str_ip << " is not correct." << endl;
			exit(-1);
		}
	}
	catch(...)
	{}

	// Src
	try
	{
		port_src_begin = ap.get<uint16_t>("--port-src-begin");
		port_src_begin = ntohs(port_src_begin);
	}
	catch(...)
	{}
	try
	{
		port_src_end = ap.get<uint16_t>("--port-src-end");
		port_src_end = ntohs(port_src_end);
	}
	catch(...)
	{}

	// Dst
	try
	{
		port_dst_begin = ap.get<uint16_t>("--port-dst-begin");
		port_dst_begin = ntohs(port_dst_begin);
	}
	catch(...)
	{}
	try
	{
		port_dst_end = ap.get<uint16_t>("--port-dst-end");
		port_dst_end = ntohs(port_dst_end);
	}
	catch(...)
	{}
	

	// Filter
	Filter filter;

	filter.proto = proto;

	filter.ip_src_begin = ip_src_begin;
	filter.ip_src_end = ip_src_end;

	filter.ip_dst_begin = ip_dst_begin;
	filter.ip_dst_end = ip_dst_end;

	filter.port_src_begin = port_src_begin;
	filter.port_src_end = port_src_end;

	filter.port_dst_begin = port_dst_begin;
	filter.port_dst_end = port_dst_end;

	cout << "Info:" << endl;
	cout << "Proto id: " << (uint32_t)filter.proto << endl;
	cout << "ip s b: " << ToIP(filter.ip_src_begin) << endl;
	cout << "ip s e: " << ToIP(filter.ip_src_end) << endl;
	cout << "ip d b: " << ToIP(filter.ip_dst_begin) << endl;
	cout << "ip d e: " << ToIP(filter.ip_dst_end) << endl;
	cout << "port s b: " << ntohs(filter.port_src_begin) << endl;
	cout << "port s e: " << ntohs(filter.port_src_end) << endl;
	cout << "port d b: " << ntohs(filter.port_dst_begin) << endl;
	cout << "port d e: " << ntohs(filter.port_dst_end) << endl;
		

	// Open array
	string path_to_file;
	path_to_file.resize(PATH_MAX, '\0');
	std::snprintf(path_to_file.data(), PATH_MAX, "/sys/fs/bpf/%s/xdp_config_map", dev.c_str());
	int fd = bpf_obj_get(path_to_file.c_str());
	if (fd < 0) {
		fprintf(stderr,
			"ERROR: Failed to open bpf map file.\n");
			exit(-1);
	}
	
	// Find free space
	size_t pos;
	Filter value;
	for (pos = 0; pos < 256; pos++)
	{
		if((bpf_map_lookup_elem(fd, &pos, &value)) != 0)
		{
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed pos:0x%X\n", pos);
			exit(-1);
		}
			
		if (value.proto == 0)
		{
			cout << "pos: " << pos << endl;
			if ((bpf_map_update_elem(fd, &pos, &filter, BPF_ANY)) != 0) {
				fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed pos:0x%I64u\n", pos);
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
void CommandClear(ArgumentParser& ap)
{
	if (ap.size() < 3)
	{
		cout << "Error: The network device name was not specified." << endl;
		exit(-1);
	}
	auto dev = ap[2];

	string path_to_file;
	path_to_file.resize(PATH_MAX, '\0');
	std::snprintf(path_to_file.data(), PATH_MAX, "/sys/fs/bpf/%s/xdp_config_map", dev.c_str());
	int fd = bpf_obj_get(path_to_file.c_str());
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

	for (size_t pos = 0; pos < 256; pos++)
	{
		Filter f;
		if ((bpf_map_update_elem(fd, &pos, &f, BPF_ANY)) != 0) {
				fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed pos:0x%X\n", pos);
				exit(-1);
			}
	}
}
