#include "zorpinvader.h"
#include "util-logger.h"
#include "crypto-blackrock.h"


void
main_listscan(struct Zorp *zorp)
{
    uint64_t i;
    uint64_t range;
    uint64_t start;
    uint64_t end;
    struct BlackRock blackrock;
    unsigned increment = zorp->shard.of;
    uint64_t seed = zorp->seed;

    /* If called with no ports, then create a pseudo-port needed
     * for the internal algorithm. */
    if (!massip_has_target_ports(&zorp->targets))
        rangelist_add_range(&zorp->targets.ports, 80, 80);
    massip_optimize(&zorp->targets);

    /* The "range" is the total number of IP/port combinations that
     * the scan can produce */
    range = massip_range(&zorp->targets).lo;


infinite:
    blackrock_init(&blackrock, range, seed, zorp->blackrock_rounds);

    start = zorp->resume.index + (zorp->shard.one-1);
    end = range;
    if (zorp->resume.count && end > start + zorp->resume.count)
        end = start + zorp->resume.count;
    end += (uint64_t)(zorp->retries * zorp->max_rate);

    for (i=start; i<end; ) {
        uint64_t xXx;
        unsigned port;
        ipaddress addr;

        xXx = blackrock_shuffle(&blackrock,  i);

        massip_pick(&zorp->targets, xXx, &addr, &port);
        

        if (zorp->is_test_csv) {
            /* [KLUDGE] [TEST]
             * For testing randomness output, prints last two bytes of
             * IP address as CSV format for import into spreadsheet
             */
            printf("%u,%u\n",(addr.ipv4>>8)&0xFF, (addr.ipv4>>0)&0xFF);
        } else if (zorp->targets.count_ports == 1) {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            /* This is the normal case */
            printf("%s\n", fmt.string);
        } else {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            if (addr.version == 6)
                printf("[%s]:%u\n", fmt.string, port);
            else
                printf("%s:%u\n", fmt.string, port);
        }

        i += increment; /* <------ increment by 1 normally, more with shards/NICs */
    }

    if (zorp->is_infinite) {
        seed++;
        goto infinite;
    }
}
