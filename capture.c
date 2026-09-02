/**************************************************************
 *
 *                     capture.c
 *
 *     Author:  Jennifer Perez 
 *     Date:    Aug, 2026
 *
 *     Summary
 *
 *     This file is called from sniffer.c. Its job is to 
 *     discover local network interfaces, activate handles,
 *     and set filters according to the user's input.
 *     This file also passes any activated handles to the 
 *     callback function found in parser.c
 *
 **************************************************************/

#include "capture.h"
#include "parser.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*************************** finding_interface ******************************
 *
 * This function finds local network interfaces. In order for the interfaces
 * to be succesfully returned, they have to be up and running and the time
 * that this function is called, cannot be a loopback interface, and must be
 * either ethernet or wlan.
 *
 * Parameters:
 *      pcap_if_t *alldevs: represents a network interface device, *alldevs is
 *                          a LL to every device on the current network
 *
 * Return: a char pointer that represents a device on the network, if no 
 *         devices were found that satify the contraints mentioned above,
 *         this function returns NULL
 *
 * Expects: alldevs to not be NULL
 *      
 * Notes:
 *      if no device is found, then this function should return NULL
 ************************************************************************/
char* finding_interface(pcap_if_t *alldevs)
{
    // if alldevs is NULL, something went wrong, so EXIT_FAILURE
    if (alldevs == NULL) {
        fprintf(stderr, "ERROR: alldevs is NULL\n");
        exit(EXIT_FAILURE);
    }

    char *dev = NULL;
    pcap_if_t *device = NULL;

    // checks that the device is up and running, is not a loopback, and is 
    // either ethernet or wlan
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

/******************************** setup **********************************
 *
 * This function creates, activates, and returns a device handler for 
 * a successfully found device on the network
 *
 * Parameters:
 *      char *device: takes in a char pointer returned from finding_interface
 *                    to create a handle from
 *
 * Return: returns a pcap_t pointer (the packet capture handler)
 *
 * Expects: the device to either be NULL or a valid device
 *      
 * Notes:
 *      device can be null and therefore must be checked. 
 ************************************************************************/
pcap_t* setup(char *device)
{
    if (device == NULL) {
        fprintf(stderr, 
        "No valid devices were found, please check your permissions and try again\n");
        exit(EXIT_FAILURE);
    }
    char errbuff[PCAP_ERRBUF_SIZE]; // in case there's an error
    pcap_t *handle = pcap_create(device, errbuff); // create the handle
    if (handle == NULL) {
        fprintf(stderr, "Pcap create failed: %s\n", errbuff);
        exit(EXIT_FAILURE);
    }
    int code = pcap_activate(handle); // activate the handle
    if (code < 0) { // unacceptable code, just exit
        fprintf(stderr, "Unable to activate handle, please try again\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    } else if (code > 0) { // exit, but not a serious issue
        fprintf(stderr, "WARNING: error code %d, please check the documentation and try again", code);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    return handle;
}

/***************************** filter_set ********************************
 *
 * This function sets any filters that were passed in on the command line
 *
 * Parameters:
 *      pcap_t *handle: the packet handler
 *      char *filter: the filter passed in from the command line
 *
 * Return: nothing, it only sets the filter using libpcap, no return needed
 *
 * Expects: filter can be NULL, but expects handle to not be NULL
 *      
 * Notes:
 *      if filter is NULL, the program will capture all traffic
 ************************************************************************/
void filter_set(pcap_t *handle, char *filter) 
{
    if (handle == NULL) {
        fprintf(stderr, "pcap_t is NULL\n");
        exit(EXIT_FAILURE);
    }
    if (filter == NULL || strlen(filter) == 0) { // capture everything
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

/***************************** sniff_loop ********************************
 *
 * This function initiates the main control loop that parses packets and 
 * finds threats
 *
 * Parameters:
 *      pcap_t *handle: the packet handler
 *
 * Return: nothing, it only operates as the control loop
 *
 * Expects: handle to not be NULL
 *      
 * Notes:
 *      this function calls pcap_loop which is actually where the main 
 *      control loop happens
 ************************************************************************/
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