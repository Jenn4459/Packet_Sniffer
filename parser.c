/**************************************************************
 *
 *                     parser.c
 *
 *     Author:  Jennifer Perez 
 *     Date:    Aug, 2026
 *
 *     Summary
 *
 *     This file is called from capture.c. Its job is to declare
 *     the containers for each packet element including headers
 *     and payload, typecast raw binary to structured protocol
 *     boundaries including header length and payload length 
 *     calculations. The callback function directly calls the
 *     main threat detector function in detector.c.
 *
 **************************************************************/

#include "parser.h"
#include "detector.h"

#include <stdio.h>
#include <stdlib.h>

/**************************** packet_handler ********************************
 *
 * This is a callback function for pcap_loop. It deconstructs the different
 * parts of the packet (headers and payload), calculates the payload length
 * and passes it along to detector.c
 *
 * Parameters:
 *      u_char *user: unused, void
 *      const struct pcap_pkthdr *h: unused, void
 *      const u_char *packet: the packet to be deconstructed
 *
 * Return: nothing, all other processes will now happen in this handler
 *
 * Expects: packet to not be NULL, but this was already checked on libpcap's
 *          end
 *      
 * Notes:
 *      
 **************************************************************************/
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
    if (ip->ip_p != 6) { 
        return;
    }
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