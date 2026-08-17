#ifndef PARSER_H
#define PARSER_H

#include <pcap/pcap.h>

typedef unsigned char u_char;
void packet_handler(u_char *user, const struct pcap_pkthdr *h, 
    const u_char *bytes);

#endif