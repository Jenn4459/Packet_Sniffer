#include "parser.h"

#include <stdio.h>
#include <stdlib.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *h,
    const u_char *bytes)
{
    (void)user;
    (void)h;
    (void)bytes;
}