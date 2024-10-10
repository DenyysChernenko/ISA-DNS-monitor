#include <stdio.h>
#include <stdint.h>
#include "arguments-parse.h"

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H


// DNS Header structure
typedef struct DNS_HEADER  {
    uint16_t id; // Unique identifier

    // Flags (detailed)
    uint16_t qr : 1;     // One bit specified whether this is a query or response
    uint16_t opcode : 4; // Specifies type of query (standard query, inverse query etc.)
    uint16_t aa : 1;     // Authoritative Answer (valid in responses)
    uint16_t tc : 1;     // TrunCation  (if message was truncated due to length)
    uint16_t rd : 1;     // Recursion Desired (if set it directs name server to pursue the query recursively)
    uint16_t ra : 1;     // Recursion Available 
    uint16_t z  : 3;     // Reserved for future (must be zero in all queries/responses)
    uint16_t rcode: 4;   // part of response (0 - no error, more than 0 some issues)

    uint16_t q_count;  // Number of entries in the question section (Questions)
    uint16_t an_count; // Number of resource records in the answer section (Answers)
    uint16_t ns_count; // Number of name servers (Authority)
    uint16_t ar_count; // Number of Additional resource (Additional)

    // Optional only in responses
    uint16_t ad     : 1;    // Authenticated Data 
    uint16_t cd     : 1;    // Checking Disabled 
} dns_header;


// Question section (for queries)
typedef struct QUESTION {
    char *qname;        // Domain name
    uint16_t qtype;     // Type of query
    uint16_t qclass;    // Class of query (ex. IN for the Internet)
} question;


// Resource Record structure (ex. Answers, Authority, Additional sections)
typedef struct RESOURCE_RECORD {
    char *name;         // Domain name 
    uint16_t type;      // Type of resource record (A, AAAA etc.)
    uint16_t a_class;   // Class of the resourse record (ex. IN for the Internet) 
    uint32_t ttl;       // Time to live
    uint16_t rdlength;  // length of RDATA
    char *rdata;        // Resourse data (ex. an IP adress)
} resource_record;


// DNS Packet structure
typedef struct DNS_PACKET {
     dns_header header;            //  DNS Header
     question *questions;          // Array of questions
     resource_record *answers;     // Array of answer resourse records
     resource_record *authorities; // Array of authority resource records
     resource_record *additionals; // Array of additional resource records
} dns_packet;


// Function declarations
// Starting point to capture DNS packets
void start_packet_capture(Arguments *arguments);


/**
 * @brief Checks if a given network interface exists on the system
 *
 * @param interface The name of the network interface to validate
 * @return 1 if the interface exists, 0 otherwise
 */
int validate_interface(const char *interface);


/**
 * @brief Validates if a PCAP file is accessible for reading (So it can sniff for DNS packets in it).
 *
 * @param pcap_file The PCAP file to validate.
 * @return 1 if the file is accessible, 0 otherwise.
 */
int validate_pcap_file(const char *pcap_file);


#endif