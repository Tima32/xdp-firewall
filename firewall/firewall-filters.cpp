#include <iostream>
#include <linux/in.h>
#include "ArgumentParser.hpp"

#include "firewall-filters.hpp"

using namespace std;


static uint32_t ParseProto(const string& proto)
{
	uint32_t proto_num{0};

	if (proto == "icmp")
		proto_num = IPPROTO_ICMP;
	else if (proto == "tcp")
		proto_num = IPPROTO_TCP;
	else if (proto == "udp")
		proto_num = IPPROTO_UDP;

	return proto_num;
}

static void PrintHelp()
{
	static constexpr auto str = 
	"Usage: xdp-firewall [options]\n"
	"	--block [protocol]\n"
	"	--filter [protocol] [ip-src] [ip-dst] [port-src] [port-dst]\n"
	"	--range [protocol] [ip-src-begin] [ip-src-end] [ip-dst-begin] [ip-dst-end]\n"
	"		[port-src-begin] [port-src-end] [port-dst-begin] [port-dst-end]\n"
	;

	cout << str << endl;
}
static bool AddBlock(const size_t pos, const ArgumentParser& ap)
{
	try
	{
		auto& proto = ap.at(pos + 1);

		uint32_t proto_num = ParseProto(proto);
		if (proto_num == IPPROTO_IP)
		{
			cout << "Error: The protocol " << proto << " is not supported." << endl;
			return false;
		}

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


bool Filters::ParseArgs(int argc, const char** argv)
{
    ArgumentParser ap(argc, argv);

	auto help_pos = ap.find("--help");
	if (help_pos != ArgumentParser::not_found || argc == 1)
	{
		PrintHelp();
		return 0;
	}

	try
	{
		// -b

		// --block
		for (size_t pos = 0; pos < ap.size(); pos++)
		{
			pos = ap.find("--block", pos);
			if (pos == -1) break;
			AddBlock(pos, ap);
		}

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
	
	return 0;
}

std::vector<uint32_t> Filters::block_proto;