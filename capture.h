#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

char* finding_interface(pcap_if_t *alldevs);
pcap_t* setup(char *device);
void filter_set(pcap_t *handle, char *filter);
void sniff_loop(pcap_t *handle);

#endif