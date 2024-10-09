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

// Function to parse arguments and store it into declared structure "Arguments"
Arguments *arguments_parsing(int argc, char **argv);


#endif