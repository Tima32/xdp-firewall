 #include "ArgumentParser.hpp"
 #include "firewall-filters.hpp"

extern bool GetDevice(ArgumentParser& ap);

void CommandAdd(ArgumentParser& ap)
{
	if (!GetDevice(ap))
		exit(-1);

	Filters::ParseArgs(ap);
	Filters::InitFiltersArray();
}