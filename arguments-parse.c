#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <unistd.h>
#include "arguments-parse.h"


void help() {
     printf("Usage: ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n");
     printf("Arguments which can be provided (with description):\n");
     printf(" -i <interface>        - Name of the interface.\n");
     printf(" -p <pcapfile>         - Name of the PCAP File.\n");
     printf("Note: Must be either interface or pcap file (NOT BOTH AND NOT NEITHER OF THEM)\n");
     printf(" -v                    - Verbose mode, enabling more complex output of DNS messages.\n");
     printf(" -d <domainsfile>      - Name of the file with domain names being inserted.\n");
     printf(" -t <translationsfile> - Name of the file with domain name and with their IP.\n");
     printf("\n");
     exit(EXIT_SUCCESS);
}


Arguments *arguments_parsing(int argc, char *argv[]) {

    // Create Structure for Arguments 
    Arguments *args = malloc(sizeof(Arguments));
    if(!args) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Default values (Init)
    strncpy(args->interface, "", MAX_LEN_IN);
    args->verbose = 0;
    args->pcap_file = NULL;
    args->domain_file = NULL;
    args->translation_file = NULL;

    // Parsing arguments
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(args->interface, argv[++i], MAX_LEN_IN);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            args->pcap_file = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            args->verbose = 1;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            args->domain_file = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            args->translation_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0){
            help();
            return NULL;
        } else {
            fprintf(stderr, "Unknow argument or/and missing argument%s\n", argv[i]);
            fprintf(stderr, "Try './dns-monitor -h' to see help function\n");
            free(args);
            return NULL;
        }
    }

    // Check if only one option was provided. Either PCAP File or Interface
    if(strlen(args->interface) != 0 && args->pcap_file != NULL) {
        fprintf(stderr, "Both Interface and PCAP File was provided.\n");
        fprintf(stderr, "Must be provied either Interface OR PCAP file\n");
        fprintf(stderr, "Try './dns-monitor -h' to see help function\n");
        free(args);
        return NULL;
    }

    // Check require arguments. Must be provided either Interface or PCAP File
    if(strlen(args->interface) == 0 && args->pcap_file == NULL) {
        fprintf(stderr, "Interface and PCAP File are missing, must be provide one from them\n");
        fprintf(stderr, "Try './dns-monitor -h' to see help function\n");
        free(args);
        return NULL;
    }
    
    return args;
}