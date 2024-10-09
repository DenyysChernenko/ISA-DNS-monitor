#include <stdio.h>
#include <stdlib.h>
#include "arguments-parse.h"
#include <unistd.h>


int main(int argc, char *argv[]) {


    Arguments *arguments = arguments_parsing(argc, argv);

    if(arguments == NULL) {
        fprintf(stderr, "Failed to parse arguments\n");
        return EXIT_FAILURE;
    }

    // Debugging printfs
    printf("Interface: %s\n", arguments->interface);
    printf("Verbose: %d\n", arguments->verbose);
    printf("PCAP File: %s\n", arguments->pcap_file ? arguments->pcap_file : "Not provided");
    printf("Domain File: %s\n", arguments->domain_file ? arguments->domain_file : "Not provided");
    printf("Translation File: %s\n", arguments->translation_file ? arguments->translation_file : "Not provided");


    free(arguments);
    return EXIT_SUCCESS;
}