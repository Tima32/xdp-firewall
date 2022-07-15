#include <iostream>
#include "ArgumentParser.hpp"

using namespace std;

struct Felter
{
	uint8_t proto;

	uint32_t ip_src;
	uint32_t ip_dst;
	
	uint16_t port_src;
	uint16_t port_dst;
};

bool AddFilter(const size_t pos, const ArgumentParser& ap)
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
int main(int argc, const char** argv)
{
	ArgumentParser ap(argc, argv);

	try
	{
		for (size_t pos = 0; pos < ap.size(); pos++)
		{
			pos = ap.find("-f", pos);
			if (pos == -1) break;
			cout << ap[pos] << " " << pos << endl;
			AddFilter(pos, ap);
		}		
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		exit(-1);
	}
	

	cout << "Hello world" << endl;
	return 0;
}
