#ifndef DETECTOR_H
#define DETECTOR_H

#define _GNU_SOURCE

    #include <pcap/pcap.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <stdbool.h>
    #include <string.h>

    typedef unsigned char  u_char;
    typedef unsigned short u_short;
    typedef unsigned int   u_int; 

    struct sniff_ethernet;
    struct sniff_ip;
    struct sniff_tcp;

    void threat_checks(const struct sniff_ip *ip, const struct sniff_tcp *tcp, 
        const u_char *payload, u_int payload_len, 
        const struct sniff_ethernet *ethernet);

    int check_flags(const struct sniff_tcp *tcp);
    int check_signatures(const u_char *payload, u_int payload_len);
    bool check_rst_rates(const struct sniff_tcp *tcp);
    bool check_syn_rates(const struct sniff_tcp *tcp);

#endif