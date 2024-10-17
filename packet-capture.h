#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include "arguments-parse.h"
#include "domain-file-handle.h"

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H


// DNS Header structure
typedef struct DNS_HEADER  {
    uint16_t id; // Unique identifier

    // Flags (detailed)
    // uint16_t qr : 1;     // One bit specified whether this is a query or response    
    // uint16_t opcode : 4; // Specifies type of query (standard query, inverse query etc.)
    // uint16_t aa : 1;     // Authoritative Answer (valid in responses)
    // uint16_t tc : 1;     // TrunCation  (if message was truncated due to length)
    // uint16_t rd : 1;     // Recursion Desired (if set it directs name server to pursue the query recursively)
    // uint16_t ra : 1;     // Recursion Available 
    // uint16_t z  : 3;     // Reserved for future (must be zero in all queries/responses)
    // uint16_t rcode: 4;   // part of response (0 - no error, more than 0 some issues)

    uint16_t flags; 

    uint16_t q_count;  // Number of entries in the question section (Questions)
    uint16_t an_count; // Number of resource records in the answer section (Answers)
    uint16_t ns_count; // Number of name servers (Authority)
    uint16_t ar_count; // Number of Additional resource (Additional)

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


    // SOA attributes
    char *mname;
    char *rname;
    uint32_t serial_number;
    uint32_t refresh_interval;
    uint32_t retry_interval;
    uint32_t expire_limit;
    uint32_t minimum_ttl;

    // MX attributes
    uint16_t preference;
    char *mail_exchange;

    // SRV attributes
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char *target; 

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
 * @brief Validates if a PCAP file is accessible for reading (So it can sniff for DNS packets in it)
 *
 * @param pcap_file The PCAP file to validate
 * @return 1 if the file is accessible, 0 otherwise
 */
int validate_pcap_file(const char *pcap_file);

/**
 * @brief Prints the details of a DNS header (with debugging purposes)
 *
 *
 * @param header Pointer to a dns_header structure that contains the DNS header information
 */
void print_dns_header(dns_header *header);


/**
 * @brief Parses resource records from a DNS packet.
 *
 * This function reads resource records from a DNS packet and stores
 * them in the provided array(Such as answers, authorities or additionals).
 *
 * @param reader current position in the packet being parsed
 * @param records array to store the parsed resource records
 * @param count number of resource records to parse
 * @param packet original DNS packet data
 */
void support_resource_record_parser(const u_char **reader, resource_record *records, int count, const u_char *packet);

/**
 * @brief Parses a DNS packet and extracts its components
 *
 * This function takes a raw DNS packet, extracts and decodes its header
 * question, answer, authority, and additional sections
 * 
 * @param packet raw DNS packet data
 * @param dns  dns_packet structure where parsed data will be stored.
 */
void support_dns_packet_parser(const u_char *packet, dns_packet *dns);

/**
 * @brief Handles and processes incoming DNS packets in non verbose mode (not complex output)
 *
 *
 * @param user_data Extra data you can pass to the handler (not used here)
 * @param pkthdr  A pointer to the packet header with details about the captured packet
 * @param packet A pointer to the actual packet data from the network
 */
void non_verbose_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);


/**
 * @brief Handles and processes incoming DNS packets in non verbose mode (complex output)
 *
 *
 * @param user_data Extra data you can pass to the handler (not used here)
 * @param pkthdr  A pointer to the packet header with details about the captured packet
 * @param packet A pointer to the actual packet data from the network
 */
void verbose_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);


/**
 * @brief Support function for settuping filters (made for comfort using)
 *
 *
 * @param handle A pointer to the pcap handle for the capture or file to apply the filter on
 * @param filter_exp  A string containing the filter expression to be set
 * @param net The network address associated with the capture device, set to 0 for offline capture
 * @return A pointer to the pcap handle if the filter is set successfully; NULL if some error occurs
 */
pcap_t *setup_filter(pcap_t *handle, char *filter_exp, bpf_u_int32 net);


void insert_if_valid(Hash_Domain_Table* hash_table, const char* domain_name);

#endif