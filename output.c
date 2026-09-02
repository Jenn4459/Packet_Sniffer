/******************************************************************************
 *
 *                     detector.c
 *
 *     Author:  Jennifer Perez 
 *     Date:    Aug, 2026
 *
 *     Summary
 *
 *     This file is called from detector.c and is the file phase (phase 4)
 *     of the program. It checks the active threats and classifies them as 
 *     either MEDIUM or CRITICAL, appending the threat summaries to a 
 *     threat log file.
 *
 *****************************************************************************/
#include "output.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**************************** output_results *******************************
 *
 * This function outputs the results of the detector.c functions. If all
 * threats were detected, a CRITICAL threat is output, if 1-3 threats were
 * found, a MEDIUM threat is output, and if no threats were found, nothing 
 * is output
 *
 * Parameters:
 *      int flags: attack code for flag attacks
 *      int sig: attack code for signature attacks
 *      bool rst: boolean for a rst flood attack
 *      bool syn: boolean for a syn flood attack
 *
 * Return: nothing, appends to a file and the program ends upon Ctrl-C in 
 *         terminal
 *
 * Expects: 
 *      
 * Notes: 
 *      
 **************************************************************************/
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