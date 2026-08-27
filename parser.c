#include "parser.h"
#include "detector.h"

#include <stdio.h>
#include <stdlib.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *h,
    const u_char *packet)
{
    (void)user;
    (void)h;
    // Delcaring containers
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;

    u_int size_ip;
    u_int size_tcp;

    // Typecasting
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    // Calling phase 3
    u_int payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
    threat_checks(ip, tcp, payload, payload_len, ethernet);
}