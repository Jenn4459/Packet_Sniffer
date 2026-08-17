#include "capture.h"
#include "parser.h"
#include "detector.h"
#include "output.h"
#include "externs.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>


int main(int argc, char *argv[])
{
    // checking for the proper arguments
    char *filter = NULL;
    if (argc == 2) {
        filter = argv[1]; //check for valid filter in the filter function
    } else if (argc == 1) {
        filter = "";
    } else if (argc > 2) {
        printf("Too many arguments!\n");
        exit(EXIT_FAILURE); 
    }

    //phase 1 -- put this is separate function later
    pcap_if_t *alldevs = NULL;
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuff) == -1) {
        fprintf(stderr, "ERROR: pcap_findalldevs failed --> %s", errbuff);
        exit(EXIT_FAILURE);
    }
    char *device = finding_interface(alldevs);
    if (device == NULL) {
        exit(EXIT_FAILURE);
    }
    pcap_freealldevs(alldevs);
    pcap_t *handle = setup(device);
    filter_set(handle, filter);
    sniff_loop(handle); //memory errors (handler unfinished tho)
    free(device);
    pcap_close(handle);

    return 0;
}