#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "packet-capture.h"


int validate_interface(const char *interface) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int interface_exist_flag = 0;

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Cannot find any device %s\n", errbuf);
        return 0;
    }

    for(pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        if(strcmp(dev->name, interface) == 0) {
            interface_exist_flag = 1;
            break;
        }
    }

    pcap_freealldevs(alldevs);
    return interface_exist_flag;
}


int validate_pcap_file(const char *pcap_file) {
    if (access(pcap_file, R_OK) != 0) {
        perror("PCAP file cannot be accessed");
        return 0;
    }
    return 1;
}


void start_packet_capture(Arguments *arguments) {

    // Debuggin prints
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
    printf("\n");



    if (strlen(arguments->interface) > 0) {
        if(validate_interface(arguments->interface)) {
            printf("Interface: %s is valid\n", arguments->interface);
        } else {
            fprintf(stderr, "Interface '%s' doesnt exist\n", arguments->interface);
            return;
        }
    }

    if(arguments->pcap_file) {
        if(validate_pcap_file(arguments->pcap_file)) {
            printf("PCAP File %s is valid\n", arguments->pcap_file);
        } else {
            fprintf(stderr, "PCAP File is not valid\n");
            return;
        }
    }

}
