#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <pcap.h>
#include <unistd.h>
#include "packet-capture.h"
#include "domain-file-handle.h"

Hash_Domain_Table *hash_table = NULL;

void insert_if_valid(Hash_Domain_Table* hash_table, const char* domain_name) {
    if (strlen(domain_name) > 0 && hash_table != NULL) {
        char modified_domain_name[256];
        strncpy(modified_domain_name, domain_name, sizeof(modified_domain_name) - 1);
        modified_domain_name[sizeof(modified_domain_name) - 1] = '\0'; 

        size_t len = strlen(modified_domain_name);
        if (len > 0 && modified_domain_name[len - 1] == '.') {
            modified_domain_name[len - 1] = '\0'; 
        }

        insert_domain_into_hashtable(hash_table, modified_domain_name);
    }
}

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

    // Supportive print for seeing all valid interfaces
    if (!interface_exist_flag) {
        printf("The specified interface '%s' is not valid. Here are the available interfaces:\n", interface);
        for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
            printf(" - %s\n", dev->name);
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

void print_dns_header(dns_header *header) {
    printf("DNS Header Information:\n");
    printf("Identifier: 0x%04X\n", header->id);
    
    printf("Flags:\n");
    printf("  QR: %d\n", (header->flags & 0x8000) >> 15);
    printf("  OPCODE: %d\n", (header->flags & 0x7800) >> 11);
    printf("  AA: %d\n", (header->flags & 0x0400) >> 10);
    printf("  TC: %d\n", (header->flags & 0x0200) >> 9);
    printf("  RD: %d\n", (header->flags & 0x0100) >> 8);
    printf("  RA: %d\n", (header->flags & 0x0080) >> 7);
    printf("  Z: %d\n", (header->flags & 0x0070) >> 4);
    printf("  AD: %d\n", (header->flags & 0x0020) >> 5);
    printf("  CD: %d\n", (header->flags & 0x0010) >> 4);
    printf("  RCODE: %d\n", header->flags & 0x000F);

    printf("Questions Count: %d\n", header->q_count);
    printf("Answer Count: %d\n", header->an_count);
    printf("Authority Count: %d\n", header->ns_count);
    printf("Additional Count: %d\n", header->ar_count);
}

void parse_dns_name(const u_char **reader, const u_char *packet, char *buffer, int *len) {
    const u_char *dns_start_temp = packet + 14 + sizeof(struct ip) + sizeof(struct udphdr);
    int jumped = 0; 
    int offset;    
    int pos = 0;    
    const u_char *orig_reader = *reader; 
    buffer[0] = '\0';

    while (**reader != 0) {
        if ((**reader & 0xc0) == 0xc0) {
            offset = ntohs(*(uint16_t *)*reader) & 0x3FFF;  
            (*reader) += 2;  

            if (!jumped) { 
                orig_reader = *reader;  
            }
            (*reader) = dns_start_temp + offset; 
            jumped = 1;  
        } else {
            int label_length = **reader; 
            (*reader)++;
            if (label_length > 0) {
               if (pos + label_length + 1 >= 256) { 
                    fprintf(stderr, "Buffer overflow prevented in DNS name parsing\n");
                    exit(EXIT_FAILURE);
                }
                
                strncpy(buffer + pos, (char *)(*reader), label_length);  
                pos += label_length;
                buffer[pos++] = '.'; 
                (*reader) += label_length; 
            } 
        }
    }

    


    if (pos > 0) {
        buffer[pos - 1] = '.';  
    }
    buffer[pos] = '\0'; 
    if (jumped) {
        *reader = orig_reader;  
    } else {
        (*reader)++;  
    }

    *len = pos + 1; 

}



void support_resource_record_parser(const u_char **reader, resource_record *records, int count, const u_char *packet) {
    for (int i = 0; i < count; i++) {
        records[i].name = (char *)malloc(256);

        if (records[i].name == NULL) {
            fprintf(stderr, "Failed to allocate memory for resource record\n");
            exit(EXIT_FAILURE);
        }

        int name_length = 0;
        parse_dns_name(reader, packet, records[i].name, &name_length);
        insert_if_valid(hash_table, records[i].name);



        
        records[i].type = ntohs(*(uint16_t *)(*reader));
        (*reader) += 2;
        records[i].a_class = ntohs(*(uint16_t *)(*reader));
        (*reader) += 2;
        records[i].ttl = ntohl(*(uint32_t *)(*reader));
        (*reader) += 4;
        records[i].rdlength = ntohs(*(uint16_t *)(*reader));
        (*reader) += 2;

        if (records[i].rdlength <= 0) {
            fprintf(stderr, "Invalid data length, cannot be less or equal than zero\n");
            exit(EXIT_FAILURE);
        }

        if (records[i].type == 1) {  
            if (records[i].rdlength == 4) {  
                struct in_addr addr;
                memcpy(&addr, *reader, sizeof(struct in_addr));  
                records[i].rdata = (char *)malloc(INET_ADDRSTRLEN);  
                inet_ntop(AF_INET, &addr, records[i].rdata, INET_ADDRSTRLEN);  
                records[i].rdata[INET_ADDRSTRLEN - 1] = '\0';
                (*reader) += records[i].rdlength;  
            } else {
                fprintf(stderr, "Invalid rdlength for A record: expected 4, got %d\n", records[i].rdlength);
                exit(EXIT_FAILURE);
            }
        } else if (records[i].type == 28) {  
            if (records[i].rdlength == 16) {  
                struct in6_addr addr;
                memcpy(&addr, *reader, sizeof(struct in6_addr));  
                records[i].rdata = (char *)malloc(INET6_ADDRSTRLEN);  
                inet_ntop(AF_INET6, &addr, records[i].rdata, INET6_ADDRSTRLEN);  
                records[i].rdata[INET6_ADDRSTRLEN - 1] = '\0';
                  (*reader) += records[i].rdlength;  
            } else {
                fprintf(stderr, "Invalid rdlength for AAAA record: expected 16, got %d\n", records[i].rdlength);
                exit(EXIT_FAILURE);
            }
         } else if(records[i].type == 5 || records[i].type == 2) {
            // TODO 
            records[i].rdata = (char *)malloc(records[i].rdlength + 2);  
            if (records[i].rdata == NULL) {
                fprintf(stderr, "Failed to allocate memory for CNAME record\n");
                exit(EXIT_FAILURE);
            }
            parse_dns_name(reader, packet, records[i].rdata,  (int *)&records[i].rdlength);
            insert_if_valid(hash_table, records[i].rdata);
            records[i].rdata[records[i].rdlength] = '\0'; 
        } else if(records[i].type == 6) { 
            
            records[i].mname = (char *)malloc(256);
            records[i].rname = (char *)malloc(256);

            if(records[i].mname == NULL || records[i].rname == NULL) {
                fprintf(stderr, "Failed to allocate memory for either mname or rname");
                exit(EXIT_FAILURE);
            }
            
            // Parse MNAME and RNAME
            int mname_length = 0;
            parse_dns_name(reader, packet, records[i].mname, &mname_length);
            insert_if_valid(hash_table, records[i].mname);
            // printf("parsed domain name: %s\n", records[i].mname);
            int rname_length = 0;
            parse_dns_name(reader, packet, records[i].rname, &rname_length);
            insert_if_valid(hash_table, records[i].rname);
            // printf("parsed domain name: %s\n", records[i].rname);
           

            records[i].serial_number = ntohl(*(uint32_t *)(*reader));
            *reader += 4;
            records[i].refresh_interval = ntohl(*(uint32_t *)(*reader));
            *reader += 4;
            records[i].retry_interval = ntohl(*(uint32_t *)(*reader));
            *reader += 4;
            records[i].expire_limit = ntohl(*(uint32_t *)(*reader));
            *reader += 4;
            records[i].minimum_ttl = ntohl(*(uint32_t *)(*reader));
            *reader += 4;
        } else if(records[i].type == 15) {
            records[i].preference = ntohs(*(uint16_t *)(*reader)); 
            *reader += 2;
            
            records[i].rdata = (char *)malloc(records[i].rdlength + 1);
            int mail_exchange_length = 0;
            parse_dns_name(reader, packet, records[i].rdata, &mail_exchange_length); 
            insert_if_valid(hash_table, records[i].rdata);
            records[i].rdata[records[i].rdlength] = '\0';  


        } else {
            records[i].rdata = (char *)malloc(records[i].rdlength + 1);  
            memcpy(records[i].rdata, *reader, records[i].rdlength);     
            records[i].rdata[records[i].rdlength] = '\0';  
        }
    }
   
}

void support_dns_packet_parser(const u_char *packet, dns_packet *dns) {
    const u_char *dns_start = packet + 14 + sizeof(struct ip) + sizeof(struct udphdr);

    // Parse DNS header with all flags, id and counts
    dns->header = *(dns_header *)dns_start;
    dns->header.id = ntohs(dns->header.id);
    dns->header.flags = ntohs(dns->header.flags);
    dns->header.q_count = ntohs(dns->header.q_count);
    dns->header.an_count = ntohs(dns->header.an_count);
    dns->header.ns_count = ntohs(dns->header.ns_count);
    dns->header.ar_count = ntohs(dns->header.ar_count);

    // print_dns_header(&dns->header);

    const u_char *reader = dns_start + sizeof(dns_header);

    // Parse DNS Question 
    dns->questions = (question *)malloc(sizeof(question) * dns->header.q_count);

    if(dns->questions == NULL) {
        fprintf(stderr, "Failed to allocate data for DNS Questions\n");
        exit(EXIT_FAILURE);
    } 

    for (int i = 0; i < dns->header.q_count; i++) {
        dns->questions[i].qname = (char *)malloc(256);

        if(dns->questions[i].qname == NULL) {
            fprintf(stderr, "Failde to allocate memory for dns question qname\n");
            exit(EXIT_FAILURE);
        }
          int name_length = 0;
          parse_dns_name(&reader, packet, dns->questions[i].qname, &name_length);
          insert_if_valid(hash_table, dns->questions[i].qname);
          dns->questions[i].qtype = ntohs(*(uint16_t *)reader);
          reader+=2;
          dns->questions[i].qclass = ntohs(*(uint16_t *)reader);
          reader+=2;
    }

    // Parse Answer Section
    if(dns->header.an_count > 0) {
        dns->answers = (resource_record *)malloc(sizeof(resource_record) * dns->header.an_count);
        if(dns->answers == NULL) {
            fprintf(stderr, "Failed to allocate memory for dns answers\n");
            exit(EXIT_FAILURE);
        }
      
        support_resource_record_parser(&reader, dns->answers, dns->header.an_count, packet);
    }

    // Parse Authority Section
    if(dns->header.ns_count > 0) { 
       
        dns->authorities = (resource_record *)malloc(sizeof(resource_record) * dns->header.ns_count);
        if(dns->authorities == NULL) {
            fprintf(stderr, "Failed to allocate memory for dns authorities\n");
            exit(EXIT_FAILURE);
        }
        support_resource_record_parser(&reader, dns->authorities, dns->header.ns_count, packet);
    }

    // Parse Additional Section
    if(dns->header.ar_count > 0) {
        dns->additionals = (resource_record *)malloc(sizeof(resource_record) * dns->header.ar_count);
         if(dns->additionals == NULL) {
            fprintf(stderr, "Failed to allocate memory for dns additionals\n");
            exit(EXIT_FAILURE);
        }
        support_resource_record_parser(&reader, dns->additionals, dns->header.ar_count, packet);
    }



}

void verbose_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;
    struct udphdr *udp_header;
    dns_packet dns;

    // Take IP Header - 14 bytes after Ethernet header
    ip_header = (struct ip *)(packet + 14);
    // If IP protocol is not UDP -> skip (Protocol: UDP(17))
    if (ip_header->ip_p != IPPROTO_UDP) {
        return; 
    }
    // Extract UDP header 
    udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4);
    
    
    // Use support function to make comfort output 

    support_dns_packet_parser(packet, &dns);

    // Prepare timestamp for output
    char time_str[64];
    struct tm *ltime;
    time_t local_tv_sec = pkthdr->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);

    // Prepare for containing src_ip and dst_ip
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Convert IP src and IP dst from binary to string
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Get source and destination port from UDP header
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);

    // DNS Header flags
    uint16_t flags = dns.header.flags;
    uint8_t qr;
    if ((flags & 0x8000) != 0) { 
        qr = 1; 
    } else {
        qr = 0;
    }
    uint8_t opcode = (flags >> 11) & 0xF;
    uint8_t aa = (flags >> 10) & 0x1;
    uint8_t tc = (flags >> 9) & 0x1;
    uint8_t rd = (flags >> 8) & 0x1;
    uint8_t ra = (flags >> 7) & 0x1;
    uint8_t ad = (flags >> 5) & 0x1;
    uint8_t cd = (flags >> 4) & 0x1;
    uint8_t rcode = flags & 0xF;

    printf("Timestamp: %s\n", time_str);
    printf("SrcIP: %s\n", src_ip);
    printf("DstIP: %s\n", dst_ip);
    printf("SrcPort: UDP/%d\n", src_port);
    printf("DstPort: UDP/%d\n", dst_port);
    printf("Identifier: 0x%04X\n", dns.header.id);
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n", 
           qr, opcode, aa, tc, rd, ra, ad, cd, rcode);


    printf("\n[Question Section]\n");
    for (int i = 0; i < dns.header.q_count; i++) {
        const char *record_type; 
        switch (dns.questions[i].qtype) {
            case 1:
                record_type = "A";
                break;
            case 28:
                record_type = "AAAA";
                break;
            case 5:
                record_type = "CNAME";
                break;
            case 2:
                record_type = "NS";
                break;
            case 6:
                record_type = "SOA";
                break;
            case 15:
                record_type = "MX";
                break;
            default:
                record_type = "UNKNOWN";
                break;
        }
        printf("%s IN %s\n", dns.questions[i].qname, record_type);
    }


    if (dns.header.an_count > 0) {
        printf("\n[Answer Section]\n");
        for (int i = 0; i < dns.header.an_count; i++) {
            const char *record_type; 
            switch (dns.answers[i].type) {
            case 1:
                record_type = "A";
                break;
            case 28:
                record_type = "AAAA";
                break;
            case 5:
                record_type = "CNAME";
                break;
            case 2:
                record_type = "NS";
                break;
            case 6:
                record_type = "SOA";
                break;
            case 15:
                record_type = "MX";
                break;
            default:
                record_type = "UNKNOWN";
                break;
        }   
            if(strcmp(record_type, "SOA") == 0) {
                printf("%s %d IN SOA %s %s %u %u %u %u %u\n",
                    dns.answers[i].name,
                    dns.answers[i].ttl,
                    dns.answers[i].mname,
                    dns.answers[i].rname,
                    dns.answers[i].serial_number,
                    dns.answers[i].refresh_interval,
                    dns.answers[i].retry_interval,
                    dns.answers[i].expire_limit,
                    dns.answers[i].minimum_ttl);
            } else if(strcmp(record_type, "MX") == 0) {
                printf("%s %d IN MX %d %s\n",
                    dns.answers[i].name,
                    dns.answers[i].ttl,
                    dns.answers[i].preference, 
                    dns.answers[i].rdata); 

            } else {
                printf("%s %d IN %s %s\n", dns.answers[i].name, dns.answers[i].ttl, record_type, dns.answers[i].rdata);
            }
        }
    }

    if (dns.header.ns_count > 0) {
        
        printf("\n[Authority Section]\n");
        for (int i = 0; i < dns.header.ns_count; i++) {
             const char *record_type; 
            switch (dns.authorities[i].type) {
                 case 2: 
                    record_type = "NS";
                    break;
                 case 6:
                    record_type = "SOA";
                    break;
            }
            if(strcmp(record_type, "SOA") == 0) {
                printf("%s %d IN SOA %s %s %u %u %u %u %u\n",
                    dns.authorities[i].name,
                    dns.authorities[i].ttl,
                    dns.authorities[i].mname,
                    dns.authorities[i].rname,
                    dns.authorities[i].serial_number,
                    dns.authorities[i].refresh_interval,
                    dns.authorities[i].retry_interval,
                    dns.authorities[i].expire_limit,
                    dns.authorities[i].minimum_ttl);
            } else {
                printf("%s %d IN NS %s\n", dns.authorities[i].name, dns.authorities[i].ttl, dns.authorities[i].rdata);
            }
        }
    }

    if (dns.header.ar_count > 0) {
        printf("\n[Additional Section]\n");
        for (int i = 0; i < dns.header.ar_count; i++) {
            const char *record_type; 
            switch (dns.additionals[i].type) {
            case 1:
                record_type = "A";
                break;
            case 28:
                record_type = "AAAA";
                break;
            case 5:
                record_type = "CNAME";
                break;
            case 2:
                record_type = "NS";
                break;
            default:
                record_type = "UNKNOWN";
                break;
        }
            printf("%s %d IN %s %s\n", dns.additionals[i].name, dns.additionals[i].ttl, record_type, dns.additionals[i].rdata);
        }
    }

    


    printf("\n");

}



void non_verbose_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
   struct ip *ip_header;
   dns_packet dns;


   // Take IP Header - 14 bytes after Ethernet header
   ip_header = (struct ip *)(packet + 14);

    // If ip protocol is not UDP -> skip (Protocol: UDP(17))
    if (ip_header->ip_p != IPPROTO_UDP) {
        return; 
    }

   // Take DNS Header, 14 (length of Ethernet header) + IP Header + + UDP headder (fixed size -> 8 bytes) 

   support_dns_packet_parser(packet, &dns);

   // Prepare timestamp for output
   char time_str[64];
   struct tm *ltime;
   // Get the raw timestamp from packet header
   time_t local_tv_sec = pkthdr->ts.tv_sec;
   ltime = localtime(&local_tv_sec);
   strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);

   // Prepare for containing src_ip and dst_ip
   char src_ip[INET_ADDRSTRLEN];
   char dst_ip[INET_ADDRSTRLEN];

   // Convert ip src and ip dst from binary to string
   inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

   // Convert from network byte order to host byte order
    uint16_t flags = dns.header.flags;
    uint8_t qr;
    if ((flags & 0x8000) != 0) { 
        qr = 'R'; 
    } else {
        qr = 'Q';
    }

    uint16_t q_count = ntohs(dns.header.q_count);
    uint16_t an_count = ntohs(dns.header.an_count);
    uint16_t ns_count = ntohs(dns.header.ns_count);
    uint16_t ar_count = ntohs(dns.header.ar_count);

   printf("%s %s -> %s (", time_str, src_ip, dst_ip);
   printf("%c %d/%d/%d/%d)\n",
           qr,          
           q_count,          
           an_count,            
           ns_count,         
           ar_count);      
}


pcap_t *setup_filter(pcap_t *handle, char *filter_exp, bpf_u_int32 net) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse the filter exp: %s\n", filter_exp);
        return NULL;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't set filter exp: %s\n", filter_exp);
        return NULL;
    }

    return handle;
}


void start_packet_capture(Arguments *arguments) {

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "udp port 53";
    bpf_u_int32 net = 0;

    if(arguments->domain_file != NULL) {
        hash_table = create_hash_table();
    }   

    if (strlen(arguments->interface) > 0) {
        if(validate_interface(arguments->interface)) {
            handle = pcap_open_live(arguments->interface, BUFSIZ, 1, 1000, errbuf);
            if(handle == NULL) {
                fprintf(stderr, "Failed to open interface %s: %s\n", arguments->interface, errbuf);
                return;
            }

            if(setup_filter(handle, filter_exp, net) == NULL) {
                pcap_close(handle);
                return;
            }
            if(arguments->verbose == 1)  {
                pcap_loop(handle, 0, verbose_packet_handler, NULL);
            } else {
                pcap_loop(handle, 0, non_verbose_packet_handler, NULL);
            }
            pcap_close(handle);

        } else {
            fprintf(stderr, "Interface '%s' doesnt exist\n", arguments->interface);
            return;
        }
    }

    if(arguments->pcap_file) {
        if(validate_pcap_file(arguments->pcap_file)) {
            handle = pcap_open_offline(arguments->pcap_file, errbuf);

            if(handle == NULL) {
                fprintf(stderr, "Coudldn't open the PCAP File %s: %s\n", arguments->pcap_file, errbuf);
                return;
            }

            if(setup_filter(handle, filter_exp, net) == NULL) {
                pcap_close(handle);
                return;
            }

            if(arguments->verbose == 1) {
                pcap_loop(handle, 0, verbose_packet_handler, NULL);
            } else {
                pcap_loop(handle, 0, non_verbose_packet_handler, NULL);
            }
                pcap_close(handle);

        } else {
            fprintf(stderr, "PCAP File is not valid\n");
            return;
        }
    }

    if(arguments->domain_file) {
        write_domains_to_file(hash_table, arguments->domain_file); 
    }
}
