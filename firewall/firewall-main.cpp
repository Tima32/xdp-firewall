#include <iostream>
#include "firewall-filters.hpp"

using namespace std;

int main(int argc, const char** argv)
{
	Filters::ParseArgs(argc, argv);
	
	cout << "Numbers of blocked protocols: ";
	for (size_t i = 0; i < Filters::block_proto.size(); ++i)
		cout << Filters::block_proto[i] << " ";
	cout << endl;

	return 0;
}
