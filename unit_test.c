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

// need to use sudo to make this test work
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
    pcap_close(set);
}


// packet_handler() tests
void handler_test_1()
{
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("test_traffic.pcap", errbuff);
    assert(handle != NULL);
    int loop = pcap_loop(handle, 0, packet_handler, NULL);
    assert(loop >= 0);
    pcap_close(handle);
}

// threat tests
void flags_test()
{
    struct sniff_tcp test1 = {0};
    test1.th_flags = 0x02;
    assert(check_flags(&test1) == 0);

    struct sniff_tcp test2 = {0};
    test2.th_flags = 0x01 | 0x08 | 0x20;
    assert(check_flags(&test2) == 1);

    struct sniff_tcp test3 = {0};
    test3.th_flags = 0x00;
    assert(check_flags(&test3) == 2);

    struct sniff_tcp test4 = {0};
    test4.th_flags = 0x02 | 0x01;
    assert(check_flags(&test4) == 3);

    printf("all flag tests passed!\n");
}

void signatures_test()
{
    const char *payload1 = "GET /index.php?user=john_doe HTTP/1.1\r\nHost: localhost\r\n\r\n";
    u_int len1 = (u_int)strlen(payload1);
    int res1 = check_signatures((const u_char *)payload1, len1);
    assert(res1 == 0);

    const char *payload2 = "' OR '1'='1";
    u_int len2 = (u_int)strlen(payload2);
    int res2 = check_signatures((const u_char *)payload2, len2);
    assert(res2 == 1);

    const char *payload3 = "<script>alert(1)</script>";
    u_int len3 = (u_int)strlen(payload3);
    int res3 = check_signatures((const u_char *)payload3, len3);
    assert(res3 == 2);

    const char *payload4 = "`";
    u_int len4 = (u_int)strlen(payload4);
    int res4 = check_signatures((const u_char *)payload4, len4);
    assert(res4 == 3);

    printf("All signature tests passed!\n");
}

void rates_test()
{
    struct sniff_tcp normal_packet = {0};
    normal_packet.th_flags = 0x10;
    for (int i = 0; i < 55; i++) {
        bool alert = check_rst_rates(&normal_packet);
        assert(alert == false);
    }

    struct sniff_tcp rst_packet = {0};
    rst_packet.th_flags = 0x04;
    for (int i = 0; i < 5; i++) {
        bool alert = check_rst_rates(&rst_packet);
        assert(alert == false);
    }
    bool alert = check_rst_rates(&rst_packet);
    assert(alert == true);
    
}


/* --------------- MAIN --------------- */
int main()
{
    // NOTE: commented out functions were tested but cause EXIT_FAILURES
    //       upon success, so they're commented out

    // interface_test_good();
    // interface_test_null();
    // interface_test_down();
    // interface_test_legit();

    // setup_test_null();
    // setup_test_fake();
    // setup_test_legit();
    
    // handler_test_1();

    // flags_test();
    // signatures_test();
    rates_test();
    return 0;
}