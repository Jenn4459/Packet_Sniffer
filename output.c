#include "output.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void output_results(int flags, int sig, bool rst, bool syn)
{
    if (flags !=0 && sig != 0 && rst && syn) {
        FILE *fptr;
        fptr = fopen("sniff_results.txt", "a");
        if (fptr == NULL) {
            fprintf(stderr, "ERROR: File failed to open.\n");
            exit(EXIT_FAILURE);
        }
        fprintf(fptr, "======================================================================\n");
        fprintf(fptr, "THREAT REPORT: sniffer v.1.1.0\n");
        time_t raw_time = time(NULL);
        fprintf(fptr, "Time: %s", ctime(&raw_time));
        fprintf(fptr, "[CRITICAL ALERT] All Threat Detectors Triggered!");
        fprintf(fptr, "Immediate attention necessary!\n");
        fprintf(fptr, "======================================================================\n");
        fclose(fptr);
        return;
    }
    if (flags != 0 || sig != 0 || rst || syn) {
        FILE *fptr;
        fptr = fopen("sniff_results.txt", "a");
        if (fptr == NULL) {
            fprintf(stderr, "ERROR: File failed to open.\n");
            exit(EXIT_FAILURE);
        }
        fprintf(fptr, "======================================================================\n");
        fprintf(fptr, "THREAT REPORT: sniffer v.1.1.0\n");
        time_t raw_time = time(NULL);
        fprintf(fptr, "Time: %s", ctime(&raw_time));
        fprintf(fptr, "[MEDIUM ALERT] At Least 1 Threat Detector Was Triggered.");
        fprintf(fptr, "The Following Attacks Have Been Identified: \n");
        if (flags !=0) {
            if (flags == 1) {
                fprintf(fptr, "Xmas attack.\n");
            } else if (flags == 2) {
                fprintf(fptr, "NULL attack.\n");
            } else {
                fprintf(fptr, "SYN-FIN attack.\n");
            }
        }
        if (sig != 0) {
            if (sig == 1) {
                fprintf(fptr, "SQL Injection\n");
            } else if (sig == 2) {
                fprintf(fptr, "XSS attack.\n");
            } else {
                fprintf(fptr, "RCE attack.\n");
            }
        }
        if (rst || syn) {
            fprintf(fptr,"DDoS Attack: \n");
            if (rst) {
                fprintf(fptr, "\tRST-flood.\n");
            }
            if (syn) {
                fprintf(fptr, "\tSYN-flood.\n");
            }
        }
        fprintf(fptr, "======================================================================\n");
        fclose(fptr);
        return;
    }
}