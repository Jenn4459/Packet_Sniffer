#include "capture.h"
#include "parser.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* finding_interface(pcap_if_t *alldevs)
{
    if (alldevs == NULL) {
        fprintf(stderr, "ERROR: alldevs is NULL\n");
        exit(EXIT_FAILURE);
    }

    char *dev = NULL;
    pcap_if_t *device = NULL;

    for (device = alldevs; device != NULL; device = device->next) {
        if (device->flags & PCAP_IF_UP && device->flags & PCAP_IF_RUNNING) {
            if (!(device->flags & PCAP_IF_LOOPBACK)) {
                if (strncmp(device->name, "eth", 3) == 0 || 
                    strncmp(device->name, "en", 2) == 0 || 
                    strncmp(device->name, "wlan0", 5) == 0) {
                        dev = strdup(device->name);
                        break;
                }
            }
        }
    }
    return dev;  
}

pcap_t* setup(char *device)
{
    if (device == NULL) {
        fprintf(stderr, 
        "No valid devices were found, please check your permissions and try again\n");
        exit(EXIT_FAILURE);
    }
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(device, errbuff);
    if (handle == NULL) {
        fprintf(stderr, "Pcap create failed: %s\n", errbuff);
        exit(EXIT_FAILURE);
    }
    int code = pcap_activate(handle);
    if (code < 0) {
        fprintf(stderr, "Unable to activate handle, please try again\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    } else if (code > 0) {
        fprintf(stderr, "WARNING: error code %d, please check the documentation and try again", code);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    return handle;
}

void filter_set(pcap_t *handle, char *filter) 
{
    if (handle == NULL) {
        fprintf(stderr, "pcap_t is NULL\n");
        exit(EXIT_FAILURE);
    }
    if (filter == NULL || strlen(filter) == 0) {
        printf("No filter specified. Capturing all traffic...\n");
        return;
    }
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, 
            pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, 
            pcap_geterr(handle));
        exit(EXIT_FAILURE);
    } 
    pcap_freecode(&fp); 
}

void sniff_loop(pcap_t *handle)
{
    if (handle == NULL) {
        fprintf(stderr, "HANDLER ERROR: Packets cannot be parsed.\n");
        exit(EXIT_FAILURE);
    }
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "LOOP ERROR: Unable to parse packets.\n");
        exit(EXIT_FAILURE);
    }
}