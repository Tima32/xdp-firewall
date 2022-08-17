#include <iostream>
#include <linux/in.h>
#include "ArgumentParser.hpp"

#include "firewall-filters.hpp"

using namespace std;

///sys/fs/bpf/wlp5s0/xdp_stats_map

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

static bool AddBlock(const size_t pos, const ArgumentParser& ap)
{
	try
	{
		auto& proto = ap.at(pos + 1);

		uint8_t proto_num = ParseProto(proto);
		if (proto_num == IPPROTO_IP)
		{
			cout << "Error: The protocol " << proto << " is not supported." << endl;
			return false;
		}

		cout << "<Filters::AddBlock>Info: Add proto " << (uint16_t)proto_num << endl;
		Filters::block_proto.push_back(proto_num);
	}
	catch (const std::exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}

	return true;
}
static bool AddFilter(const size_t pos, const ArgumentParser& ap)
{
	try
	{
		auto& proto = ap.at(pos + 1);

		cout << proto << endl;

		cout << "--------" << endl;
	}
	catch (const std::exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}

	return true;
}


bool Filters::ParseArgs(ArgumentParser& ap)
{
	try
	{
		// -b
		for (size_t pos = 0; pos < ap.size(); pos++)
		{
			pos = ap.find("-b", pos);
			if (pos == -1) break;
			AddBlock(pos, ap);
		}

		// --block
		for (size_t pos = 0; pos < ap.size(); pos++)
		{
			pos = ap.find("--block", pos);
			if (pos == -1) break;
			AddBlock(pos, ap);
		}
		// --block

		// -f
		for (size_t pos = 0; pos < ap.size(); pos++)
		{
			pos = ap.find("-f", pos);
			if (pos == -1) break;
			AddFilter(pos, ap);
		}

		// --filter

		// -r

		// --range
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		exit(-1);
	}
	
	return true;
}
void Filters::InitFiltersArray()
{
	filters.clear();

	// Bclock
	for (size_t i = 0; i < block_proto.size(); i++)
	{
		Filter f;
		f.proto = block_proto[i];
		f.ip_src = 0;
		f.ip_dst = numeric_limits<uint32_t>::max();
		f.port_src = 0;
		f.port_dst = numeric_limits<uint16_t>::max();

		filters.push_back(f);
	}
}


std::vector<uint8_t> Filters::block_proto;

std::vector<Filters::Filter> Filters::filters;
