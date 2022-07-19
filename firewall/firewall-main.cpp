#include <iostream>
#include "firewall-filters.hpp"

using namespace std;

int main(int argc, const char** argv)
{
	Filters::ParseArgs(argc, argv);

	return 0;
}
