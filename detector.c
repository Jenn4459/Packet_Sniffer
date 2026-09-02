/**************************************************************
 *
 *                     detector.c
 *
 *     Author:  Jennifer Perez 
 *     Date:    Aug, 2026
 *
 *     Summary
 *
 *     This file is called from parser.c. Its job is to identify 
 *     any threats present in the currently processing packet.
 *     All threat detecting functions are called through 
 *     threat_checks(), which then passes the result of each 
 *     function to output_results() in output.c
 *
 **************************************************************/
#include "detector.h"
#include "parser.h"
#include "output.h"

#include <stdio.h>
#include <stdlib.h>

/**************************** threat_checks ********************************
 *
 * This is the main function for detector.c. The actual threat checking 
 * function are called and returned here. This is also where the results of
 * the threat functions are passed into output_results
 *
 * Parameters:
 *      const struct sniff_ip *ip: ip header, not used
 *      const struct sniff_tcp *tcp: tcp header (for flag and rate checks)
 *      const u_char *payload: payload (for signature checks)
 *      u_int payload_len: length of the payload
 *      const struct sniff_ethernet *ethernet: ethernet header (not used)
 *
 * Return: nothing, passed straight to output.c
 *
 * Expects: packet to not be NULL, but this was already checked on libpcap's
 *          end
 *      
 * Notes: since this is called inside of the callback function, the parameters
 *        have already been verified on libpcaps end
 *      
 **************************************************************************/
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

/**************************** check_flags ********************************
 *
 * This function checks if any suspicious array of flags are turned on. The
 * attacks it looks for are XMAS, NULL, and SYN-FIN combo attacks
 *
 * Parameters:
 *      const struct sniff_tcp *tcp: needed to check the flags
 *
 * Return: an integer representing if an attack has occured and what type
 *         of attack upon positive identification
 *              0: no attacks present
 *              1: XMAS
 *              2: NULL
 *              3: SYN-FIN
 *
 * Expects: tcp to not be NULL, but this was already checked on libpcap's
 *          end
 *      
 * Notes: since this is called inside of the callback function, the parameters
 *        have already been verified on libpcaps end
 *      
 **************************************************************************/
int check_flags(const struct sniff_tcp *tcp)
{
    // XMAS
    if ((tcp->th_flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG)) {
        return 1;
    } // NULL
    if (tcp->th_flags == 0) {
        return 2;
    } // SYN-FIN
    if ((tcp->th_flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN)) {
        return 3;
    }
    return 0;
}

/*************************** check_signatures *******************************
 *
 * This function checks if any suspicious payload signatures are present. The
 * attacks it looks for are SQL injections, XSS and RCE attacks
 *
 * Parameters:
 *      const u_char *payload: the actual payload itself
 *      u_int payload_len: the payload length
 *
 * Return: an integer representing if an attack has occured and what type
 *         of attack upon positive identification
 *              0: no attacks present
 *              1: SQL injection
 *              2: XSS attack
 *              3: RCE
 *
 * Expects: payload to not be NULL, but this was already checked on libpcap's
 *          end
 *      
 * Notes: since this is called inside of the callback function, the parameters
 *        have already been verified on libpcaps end
 *      
 **************************************************************************/
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

/*************************** check_rst_rates *******************************
 *
 * This function checks if there is a suspicious amount of rst packets 
 * coming in
 *
 * Parameters:
 *      const struct sniff_tcp *tcp: tcp needed to check the flags
 *
 * Return: a boolean indicating if an attack is occuring
 *
 * Expects: payload to not be NULL, but this was already checked on libpcap's
 *          end
 *      
 * Notes: since this is called inside of the callback function, the parameters
 *        have already been verified on libpcaps end
 *      
 **************************************************************************/
bool check_rst_rates(const struct sniff_tcp *tcp)
{
    // < 10% of packets should have the rst flag on
    const float rate = 1.0f / 10.0f;
    static bool buffer[60];
    static int rst_count = 0;
    static int count = 0;
    static int last = 0;

    count++;
    // since we're utilizing a circular buffer, the function is split into
    // before the buffer is full and after
    if (count <= 60) { 
        if (tcp->th_flags & TH_RST) {
            rst_count++;
            buffer[last] = true;
        } else {
            buffer[last] = false;
        }
        float res = (float)rst_count / count;
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
        if (res >= rate) {
            return true;
        }
    }
    last = (last + 1) % 60;
    return false;
}

/*************************** check_syn_rates *******************************
 *
 * This function checks if there is a suspicious amount of syn packets 
 * coming in
 *
 * Parameters:
 *      const struct sniff_tcp *tcp: tcp needed to check the flags
 *
 * Return: a boolean indicating if an attack is occuring
 *
 * Expects: payload to not be NULL, but this was already checked on libpcap's
 *          end
 *      
 * Notes: since this is called inside of the callback function, the parameters
 *        have already been verified on libpcaps end
 *      
 **************************************************************************/
bool check_syn_rates(const struct sniff_tcp *tcp)
{
    // < 60% of packets should have SYN flag
    const float rate = 0.60;
    static bool buffer[1000];
    static int syn_count = 0;
    static int count = 0;
    static int last = 0;

    count++;
    // since we're utilizing a circular buffer, the function is split into
    // before the buffer is full and after
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