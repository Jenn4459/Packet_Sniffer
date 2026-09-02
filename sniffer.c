/**************************************************************
 *
 *                     sniffer.c
 *
 *     Author:  Jennifer Perez 
 *     Date:    Aug, 2026
 *
 *     Summary
 *
 *     The entry point for the packet sniffer application. It 
 *     processes command line arguments, discovers local 
 *     network interfaces, detecting only non-loopback interfaces
 *     as well as configuring any network filters the user passes
 *     in.
 *
 **************************************************************/
#include "capture.h"
#include "parser.h"
#include "detector.h"
#include "output.h"
#include "externs.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

/********************************** main **********************************
 *
 * The main function of the program. It processes user input, phase 1 
 * functions, the main control loop, and frees any memory allocated inside
 * of it
 *
 * Parameters:
 *      int argc: the number of arguments provided on the command line
 *      char *argv[]: char pointers to the names of the command line arguments
 *
 * Return: EXIT_SUCCESS if program makes it all the way to the end with no
 *         issues (EXIT_FAILURE is called in main and in any .c file in which
 *         an error occurs)
 *
 * Expects: arguments to not exceed 2 (name of program and filter)
 *      
 * Notes:
 *      the filter function in capture.c handles filter validity and is not
 *      a concern for main
 ************************************************************************/
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

    // phase 1 - setup, finding interfaces, and filtering
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

    // all other processes happen w/in sniff_loop
    sniff_loop(handle);
    
    free(device);
    pcap_close(handle);

    return EXIT_SUCCESS;
}