#ifndef DETECTOR_H
#define DETECTOR_H

    #include <pcap/pcap.h>
    #include <sys/types.h>
    #include <netinet/in.h>

    typedef unsigned char  u_char;
    typedef unsigned short u_short;
    typedef unsigned int   u_int; 

    struct sniff_ethernet;
    struct sniff_ip;
    struct sniff_tcp;

    void threat_checks(const struct sniff_ip *ip, const struct sniff_tcp *tcp, 
        const u_char *payload, u_int payload_len, 
        const struct sniff_ethernet *ethernet);

#endif