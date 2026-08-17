#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "assert.h"

#include "capture.h"
#include "parser.h"
#include "detector.h"
#include "output.h"

/* --------- UNIT TESTS HERE --------- */

// finding_interface() tests
void interface_test_good() 
{
    pcap_if_t good_device;
    good_device.name = "wlan0";
    good_device.flags = PCAP_IF_UP | PCAP_IF_RUNNING;
    good_device.next = NULL;

    char *device = finding_interface(&good_device);

    assert(device != NULL);
    assert(strcmp(device, "wlan0") == 0);

    free(device);
    printf("finding_interface test 'controlled' passed!!\n");
}

void interface_test_null()
{
    pcap_if_t *null = NULL;
    char *device = finding_interface(null);
    free(device);
}

void interface_test_down()
{
    pcap_if_t good_device;
    good_device.name = "wlan0";
    good_device.flags = PCAP_IF_RUNNING;
    good_device.next = NULL;

    char *device = finding_interface(&good_device);

    // assert(device != NULL);
    // assert(strcmp(device, "wlan0") == 0);
    assert(device == NULL);

    free(device);
    printf("finding_interface test 'down' passed!!\n");
}

void interface_test_legit()
{
    pcap_if_t *alldevs = NULL;
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuff) == -1) {
        fprintf(stderr, "ERROR: pcap_findalldevs failed --> %s", errbuff);
        exit(EXIT_FAILURE);
    }
    char *device = finding_interface(alldevs);
    assert(device != NULL);
    pcap_freealldevs(alldevs);
    free(device);
    printf("finding_interface test 'legit' passed!\n");
}

// setup() tests
void setup_test_null() 
{
    setup(NULL);
}

void setup_test_fake()
{
    setup("this_isnt_a_real_device");
}

void setup_test_legit()
{
    pcap_if_t *alldevs = NULL;
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuff) == -1) {
        fprintf(stderr, "ERROR: pcap_findalldevs failed --> %s", errbuff);
        return;
    }
    char *device = finding_interface(alldevs);
    if (device == NULL) {
        fprintf(stderr, "Device is NULL, skipping setup test\n");
        pcap_freealldevs(alldevs);
        return;
    }
    printf("Device: %s\n", device);
    pcap_t *set = setup(device);
    assert(set != NULL);
    printf("Setup test 'legit' passed!\n");
    pcap_freealldevs(alldevs);
    free(device);
}





/* --------------- MAIN --------------- */
int main()
{
    // NOTE: commented out functions were tested but cause EXIT_FAILURES
    //       upon success, so they're commented out

    interface_test_good();
    // interface_test_null();
    interface_test_down();
    interface_test_legit();

    // setup_test_null();
    // setup_test_fake();
    setup_test_legit();
    return 0;
}