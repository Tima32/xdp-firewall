#include <vector>
#include <stdint.h>


class Filters
{
public:
    struct Felter
    {
	    uint8_t proto;

	    uint32_t ip_src;
	    uint32_t ip_dst;
	
	    uint16_t port_src;
	    uint16_t port_dst;
    };

    static bool ParseArgs(int argc, const char** argv);

    static std::vector<uint32_t> block_proto;

    Filters() = delete;
};