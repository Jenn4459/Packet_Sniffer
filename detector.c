#include "detector.h"
#include "parser.h"
#include "output.h"

#include <stdio.h>
#include <stdlib.h>

void threat_checks(const struct sniff_ip *ip, const struct sniff_tcp *tcp, 
        const u_char *payload, u_int payload_len, 
        const struct sniff_ethernet *ethernet)
{
    (void)ip; (void)ethernet;
    int flags = check_flags(tcp);
    int sig = check_signatures(payload, payload_len);
    bool rst = check_rst_rates(tcp);
    bool syn = check_syn_rates(tcp);
    output_results(flags, sig, rst, syn);
}

int check_flags(const struct sniff_tcp *tcp)
{
    if ((tcp->th_flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG)) {
        return 1;
    }
    if (tcp->th_flags == 0) {
        return 2;
    }
    if ((tcp->th_flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN)) {
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

bool check_rst_rates(const struct sniff_tcp *tcp)
{
    const float rate = 1.0f / 10.0f;
    static bool buffer[60];
    static int rst_count = 0;
    static int count = 0;
    static int last = 0;

    count++;
    if (count <= 60) {
        if (tcp->th_flags & TH_RST) {
            rst_count++;
            buffer[last] = true;
        } else {
            buffer[last] = false;
        }
        float res = (float)rst_count / count;
        printf("rst_count: %d, count: %d", rst_count, count);
        if (res >= rate) {
            return true;
        }
    } else {
        if (buffer[last]) {
            rst_count--;
        }
        if (tcp->th_flags & TH_RST) {
            rst_count++;
            buffer[last] = true;
        } else {
            buffer[last] = false;
        }
        float res = (float)rst_count / 60.0f;
        printf("rst_count: %d, count: 60", rst_count);
        if (res >= rate) {
            return true;
        }
    }
    last = (last + 1) % 60;
    return false;
}

bool check_syn_rates(const struct sniff_tcp *tcp)
{
    const float rate = 0.60;
    static bool buffer[1000];
    static int syn_count = 0;
    static int count = 0;
    static int last = 0;

    count++;
    if (count <= 1000) {
        if (tcp->th_flags & TH_SYN) {
            syn_count++;
            buffer[last] = true;
        } else {
            buffer[last] = false;
        }
        float res = (float)syn_count / count;
        if (res >= rate) {
            return true;
        }
    } else {
        if (buffer[last]) {
            syn_count--;
        }
        if (tcp->th_flags & TH_SYN) {
            syn_count++;
            buffer[last] = true;
        } else {
            buffer[last] = false;
        }
        float res = (float)syn_count / 1000.0f;
        if (res >= rate) {
            return true;
        }
    }
    last = (last + 1) % 1000;
    return false;
}