#include <vector>
#include <stdint.h>


class Filters
{
public:
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

    static bool ParseArgs(ArgumentParser& ap);
    static void InitFiltersArray();

    static std::vector<uint8_t> block_proto;

    static std::vector<Filter> filters;

    Filters() = delete;
};