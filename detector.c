#include "detector.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>

// i will need to return something, but not sure what yet
void threat_checks(const struct sniff_ip *ip, const struct sniff_tcp *tcp, 
        const u_char *payload, u_int payload_len, 
        const struct sniff_ethernet *ethernet)
{
    (void)ip;
    (void)tcp;
    (void)payload;
    (void)payload_len;
    (void)ethernet;
}