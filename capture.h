/******************************************************************************
 *
 *                      capture.h
 *
 *      Author: Jennifer Perez
 *      Date: Aug, 2026
 *
 *                      Summary
 *
 *      This file serves as the header file for capture.c. It declares the 
 *      function prototypes used by sniffer.c to discover local network 
 *      devices, activate handles, and compile packet filtering rules.
 *
 *****************************************************************************/
#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

char* finding_interface(pcap_if_t *alldevs);
pcap_t* setup(char *device);
void filter_set(pcap_t *handle, char *filter);
void sniff_loop(pcap_t *handle);

#endif