#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "packet-capture.h"



void start_packet_capture(Arguments *arguments) {
    printf("Starting packet capture with the following settings:\n");
    if(strlen(arguments->interface) == 0) {
        printf("Interface : Not provided\n");
    } else {
        printf("Interface: %s\n", arguments->interface);
    }
    printf("Verbose: %d\n", arguments->verbose);
    printf("PCAP File: %s\n", arguments->pcap_file ? arguments->pcap_file : "Not provided");
    printf("Domain File: %s\n", arguments->domain_file ? arguments->domain_file : "Not provided");
    printf("Translation File: %s\n", arguments->translation_file ? arguments->translation_file : "Not provided");

}
