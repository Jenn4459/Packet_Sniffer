#include "detector.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>

// i will need to return something, but not sure what yet
char* threat_checks(const struct sniff_ip *ip, const struct sniff_tcp *tcp, 
        const u_char *payload, u_int payload_len, 
        const struct sniff_ethernet *ethernet)
{
    (void)ip; (void)ethernet;

    int flags = check_flags(tcp);
    int sig = check_signatures(payload, payload_len);
    bool rates = check_rates(tcp);
}

int check_flags(const struct sniff_tcp *tcp)
{
    if (tcp->th_flags & TH_FIN & TH_PUSH & TH_URG) {
        return 1;
    }
    if (tcp->th_flags == 0) {
        return 2;
    }
    if (tcp->th_flags & TH_SYN & TH_FIN) {
        return 3;
    }
    return 0;
}

int check_signatures(const u_char *payload, u_int payload_len)
{
    if (payload_len > 0 && payload != NULL) {
        // check SQL
        const char *SQL = "' OR '1'='1";
        if (memmem(payload, payload_len, SQL, strlen(SQL)) != NULL) {
            return 1;
        }
        // check XSS
        const char *XSS_1 = "<script>alert(1)</script>";
        const char *XSS_2 = "<img src=x onerror=alert(1)>";
        const char *XSS_3 = "<img src=x onerror=alert1>";
        if (memmem(payload, payload_len, XSS_1, strlen(XSS_1)) != NULL ||
            memmem(payload, payload_len, XSS_2, strlen(XSS_2)) != NULL ||
            memmem(payload, payload_len, XSS_3, strlen(XSS_3)) != NULL) {
            return 2;
        }
        // check RCE
        const char *RCE_1 = "/bin/bash";
        const char *RCE_2 = "$(cat /etc/passwd)";
        const char *RCE_3 = "`";
        const char *RCE_4 = "; ";
        const u_char buff[] = {0x90, 0x90, 0x90, 0x90};
        if (memmem(payload, payload_len, RCE_1, strlen(RCE_1)) != NULL ||
            memmem(payload, payload_len, RCE_2, strlen(RCE_2)) != NULL ||
            memmem(payload, payload_len, RCE_3, strlen(RCE_3)) != NULL ||
            memmem(payload, payload_len, RCE_4, strlen(RCE_4)) != NULL ||
            memmem(payload, payload_len, buff, sizeof(buff)) != NULL) {
            return 3;
        }
    }
    return 0;
}

bool check_rates(const struct sniff_tcp *tcp)
{
    // not using time but a rate in which rst flags are 
    // present in a window of 60 packets
    // using a circular buffer to adjust the window, but 
    // having issues with the initial setup of the array
    const float rate = 1.0f / 10.0f;
    bool buffer[60];
    bool count = 0;
    static int first = 0;
    static int last = 0;

    // if (last ) {

    // }
    if (tcp->th_flags & TH_RST) {
        buffer[last] = true;
    } else {
        buffer[last] = false;
    }

    last = (last + 1) % 60;

    return false;
}