#include <stdio.h>

#ifndef ARGUMENTS_PARCE_H
#define ARGUMENTS_PARCE_H

#define MAX_LEN_IN 256


// Arguments structure to comfortly store arguments into strucutre
typedef struct ARGUMENTS {
    char interface[MAX_LEN_IN];
    int verbose;
    char *pcap_file;
    char *domain_file;
    char *translation_file;
} Arguments;


// Function declarations
/**
 * @brief Parses command-line arguments into an Arguments structure
 *
 * @param argc The number of command-line arguments
 * @param argv An array of command-line argument strings
 * @return A pointer to an Arguments structure or NULL if parsing fails
 */
Arguments *arguments_parsing(int argc, char **argv);

/** @brief Write help message with example of usage and description of each paramater
 *
 */
void help(); 

#endif