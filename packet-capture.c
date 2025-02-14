#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h> 
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <unistd.h>
#include "packet-capture.h"
#include "domain-file-handle.h"

volatile sig_atomic_t stop_capture = 0;

Hash_Domain_Table *hash_table_domain = NULL;
Hash_Domain_Table *hash_table_domain_ip_combined = NULL;

void handle_signal(int signum) {
    printf("Received signal %d, cleaning up...\n", signum);

    stop_capture = 1; 
    cleanup_and_exit(hash_table_domain, hash_table_domain_ip_combined);
}

void cleanup_and_exit(Hash_Domain_Table *hash_table_domain, Hash_Domain_Table *hash_table_domain_ip_combined) {
    if (hash_table_domain) {
        free_hash_table(hash_table_domain);  
    }
    
    if (hash_table_domain_ip_combined) {
        free_hash_table(hash_table_domain_ip_combined);  
    }
    
    printf("Program terminated gracefully.\n");
    exit(0); 
}


void free_dns_packet(dns_packet *dns) {
    if (dns == NULL) {
        return;
    }

    if (dns->questions) {
        for (int i = 0; i < dns->header.q_count; i++) {
            if (dns->questions[i].qname) {
                free(dns->questions[i].qname);
            }
        }
        free(dns->questions); 
    }

    if (dns->header.an_count > 0) {
        for (int i = 0; i < dns->header.an_count; i++) {
            if (dns->answers[i].name) {
                free(dns->answers[i].name);     
            }
            if (dns->answers[i].rdata) {
                free(dns->answers[i].rdata);    
            }

            if (dns->answers[i].mname) {
                free(dns->answers[i].mname);      
            }
            if (dns->answers[i].rname) {
                free(dns->answers[i].rname);     
            }

            if (dns->answers[i].mail_exchange) {
                free(dns->answers[i].mail_exchange);
            }

            if (dns->answers[i].target) {
                free(dns->answers[i].target);  
            }
        }
        free(dns->answers);
    }

    if (dns->header.ns_count > 0) {
        for (int i = 0; i < dns->header.ns_count; i++) {
            if (dns->authorities[i].name) {
                free(dns->authorities[i].name);   
            }
            if (dns->authorities[i].rdata) {
                free(dns->authorities[i].rdata);   
            }

            if (dns->authorities[i].mname) {
                free(dns->authorities[i].mname);  
            }
            if (dns->authorities[i].rname) {
                free(dns->authorities[i].rname);  
            }

            if (dns->authorities[i].mail_exchange) {
                free(dns->authorities[i].mail_exchange);
            }

            if (dns->authorities[i].target) {
                free(dns->authorities[i].target);  
            }
        }
        free(dns->authorities); 
    }

    if (dns->header.ar_count > 0) {
        for (int i = 0; i < dns->header.ar_count; i++) {
            if (dns->additionals[i].name) {
                free(dns->additionals[i].name);    
            }
            if (dns->additionals[i].rdata) {
                free(dns->additionals[i].rdata);   
            }
            if (dns->additionals[i].mname) {
                free(dns->additionals[i].mname); 
            }
            if (dns->additionals[i].rname) {
                free(dns->additionals[i].rname);   
            }
            if (dns->additionals[i].mail_exchange) {
                free(dns->additionals[i].mail_exchange);
            }

            if (dns->additionals[i].target) {
                free(dns->additionals[i].target);  
            }
        }
        free(dns->additionals); 
    }

}


const char* class_to_string(uint16_t qclass) {
    switch (qclass) {
        case 1: 
            return "IN";
        default: 
            return "UNKNOWN";
    }
}

const char* get_record_type(uint16_t type) {
    switch (type) {
        case 1:  return "A";
        case 28: return "AAAA";
        case 5:  return "CNAME";
        case 2:  return "NS";
        case 6:  return "SOA";
        case 15: return "MX";
        case 33: return "SRV";
        default: return "UNKNOWN";
    }
}

void print_resource_record(const resource_record* record) {
    const char* record_type = get_record_type(record->type);
    
    if (strcmp(record_type, "SOA") == 0) {
        printf("%s %d %s SOA %s %s %u %u %u %u %u\n",
               record->name,
               record->ttl,
               class_to_string(record->a_class),
               record->mname,
               record->rname,
               record->serial_number,
               record->refresh_interval,
               record->retry_interval,
               record->expire_limit,
               record->minimum_ttl);
    } else if (strcmp(record_type, "MX") == 0) {
        printf("%s %d %s MX %d %s\n",
               record->name,
               record->ttl,
               class_to_string(record->a_class),
               record->preference,
               record->mail_exchange);
    } else if (strcmp(record_type, "SRV") == 0) {
        printf("%s %d %s SRV %u %u %u %s\n",
               record->name,
               record->ttl,
               class_to_string(record->a_class),
               record->priority,
               record->weight,
               record->port,
               record->target);
    } else if (strcmp(record_type, "UNKNOWN") == 0) {
        printf("UNKNOWN TYPE\n");
    } else {
        printf("%s %d %s %s %s\n",
               record->name,
               record->ttl,
               class_to_string(record->a_class),
               record_type,
               record->rdata);
    }
}


void insert_if_valid(Hash_Domain_Table* hash_table, const char* domain_name) {
    if (strlen(domain_name) > 0 && hash_table != NULL) {

        char modified_domain_name[256];
        strncpy(modified_domain_name, domain_name, sizeof(modified_domain_name) - 1);
        modified_domain_name[sizeof(modified_domain_name) - 1] = '\0'; 

        size_t len = strlen(modified_domain_name);
        if (len > 0 && modified_domain_name[len - 1] == '.') {
            modified_domain_name[len - 1] = '\0'; 
        }
        insert_domain_into_hashtable(hash_table_domain, modified_domain_name);
    }
}

void insert_if_valid_domain_ip(Hash_Domain_Table* hash_table, const char* domain_name, const char* ip_address) {
     if (hash_table != NULL && domain_name != NULL && ip_address != NULL) { 

    char modified_domain_name[256];
    strncpy(modified_domain_name, domain_name, sizeof(modified_domain_name) - 1);
    modified_domain_name[sizeof(modified_domain_name) - 1] = '\0'; 

    size_t len = strlen(modified_domain_name);
    if (len > 0 && modified_domain_name[len - 1] == '.') {
        modified_domain_name[len - 1] = '\0'; 
    }

    insert_domain_ip_into_hashtable(hash_table_domain_ip_combined, modified_domain_name, ip_address);
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
    const u_char *dns_start_temp;
    uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));

    if (ethertype == 0x0800) { 
        dns_start_temp = packet + 14 + sizeof(struct ip) + sizeof(struct udphdr);
    } else if (ethertype == 0x86dd) { 
        dns_start_temp = packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
    }  else {
        printf("Unsupported packet type for DNS parsing\n");
        return; 
    }


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
        insert_if_valid(hash_table_domain, records[i].name);

        records[i].type = ntohs(*(uint16_t *)(*reader));
        (*reader) += 2;
        records[i].a_class = ntohs(*(uint16_t *)(*reader));
        (*reader) += 2;
        records[i].ttl = ntohl(*(uint32_t *)(*reader));
        (*reader) += 4;
        records[i].rdlength = ntohs(*(uint16_t *)(*reader));
        (*reader) += 2;
        

        if (records[i].type != 1 && records[i].type != 2 && records[i].type != 5 &&
            records[i].type != 6 && records[i].type != 15 && records[i].type != 28 && records[i].type != 33) {
            (*reader) +=  records[i].rdlength;
            continue; 
        }

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
                insert_if_valid_domain_ip(hash_table_domain_ip_combined, records[i].name, records[i].rdata);
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
                insert_if_valid_domain_ip(hash_table_domain_ip_combined, records[i].name, records[i].rdata);
            } else {
                fprintf(stderr, "Invalid rdlength for AAAA record: expected 16, got %d\n", records[i].rdlength);
                exit(EXIT_FAILURE);
            }
         } else if(records[i].type == 5 || records[i].type == 2) {
            records[i].rdata = (char *)malloc(records[i].rdlength + 2);  
            if (records[i].rdata == NULL) {
                fprintf(stderr, "Failed to allocate memory for CNAME record\n");
                exit(EXIT_FAILURE);
            }
            parse_dns_name(reader, packet, records[i].rdata,  (int *)&records[i].rdlength);
            insert_if_valid(hash_table_domain, records[i].rdata);
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
            insert_if_valid(hash_table_domain, records[i].mname);
            int rname_length = 0;
            parse_dns_name(reader, packet, records[i].rname, &rname_length);
            insert_if_valid(hash_table_domain, records[i].rname);

           

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
            
            // records[i].rdata = (char *)malloc(records[i].rdlength + 1);
            records[i].mail_exchange = (char *)malloc(256);

            if(records[i].mail_exchange == NULL) {
                fprintf(stderr, "Failed to allocate memory for record data\n");
                exit(EXIT_FAILURE);
            }

            int mail_exchange_length = 0;
            parse_dns_name(reader, packet, records[i].mail_exchange, &mail_exchange_length); 
            records[i].mail_exchange[records[i].rdlength] = '\0';  
            insert_if_valid(hash_table_domain, records[i].mail_exchange);

        } else if (records[i].type == 33) {
            records[i].priority = ntohs(*(uint16_t *)(*reader)); 
            *reader += 2;
            records[i].weight = ntohs(*(uint16_t *)(*reader));   
            *reader += 2;
            records[i].port = ntohs(*(uint16_t *)(*reader));     
            *reader += 2;

            records[i].target = (char *)malloc(records[i].rdlength -6 + 1);
            if (records[i].target == NULL) {
                fprintf(stderr, "Failed to allocate memory for SRV target\n");
                exit(EXIT_FAILURE);
            }

            int target_length = 0;
            parse_dns_name(reader, packet, records[i].target, &target_length);
            insert_if_valid(hash_table_domain, records[i].target);
            records[i].target[target_length] = '\0'; 
    
        } else {
            records[i].rdata = (char *)malloc(records[i].rdlength + 1);  
            memcpy(records[i].rdata, *reader, records[i].rdlength);     
            records[i].rdata[records[i].rdlength] = '\0';  
        }
    }
   
}

void support_dns_packet_parser(const u_char *packet, dns_packet *dns) {
    uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));
    
    const u_char *dns_start;
    if (ethertype == 0x0800) { 
        dns_start = packet + 14 + sizeof(struct ip) + sizeof(struct udphdr);
    } else if (ethertype == 0x86dd) { 
        dns_start = packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
    }  else {
        printf("Unsupported packet type for DNS parsing\n");
        return; 
    }


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
          insert_if_valid(hash_table_domain, dns->questions[i].qname);
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
        for (int i = 0; i < dns->header.an_count; i++) {
            dns->answers[i].name = NULL;
            dns->answers[i].type = 0;
            dns->answers[i].a_class = 0;
            dns->answers[i].ttl = 0;
            dns->answers[i].rdlength = 0;
            dns->answers[i].rdata = NULL;

            dns->answers[i].mname = NULL;
            dns->answers[i].rname = NULL;
            dns->answers[i].serial_number = 0;
            dns->answers[i].refresh_interval = 0;
            dns->answers[i].retry_interval = 0;
            dns->answers[i].expire_limit = 0;
            dns->answers[i].minimum_ttl = 0;

            dns->answers[i].preference = 0;
            dns->answers[i].mail_exchange = NULL;

            dns->answers[i].priority = 0;
            dns->answers[i].weight = 0;
            dns->answers[i].port = 0;
            dns->answers[i].target = NULL;
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

        for (int i = 0; i < dns->header.ns_count; i++) {
            dns->authorities[i].name = NULL;
            dns->authorities[i].type = 0;
            dns->authorities[i].a_class = 0;
            dns->authorities[i].ttl = 0;
            dns->authorities[i].rdlength = 0;
            dns->authorities[i].rdata = NULL;

            dns->authorities[i].mname = NULL;
            dns->authorities[i].rname = NULL;
            dns->authorities[i].serial_number = 0;
            dns->authorities[i].refresh_interval = 0;
            dns->authorities[i].retry_interval = 0;
            dns->authorities[i].expire_limit = 0;
            dns->authorities[i].minimum_ttl = 0;

            dns->authorities[i].preference = 0;
            dns->authorities[i].mail_exchange = NULL;

            dns->authorities[i].priority = 0;
            dns->authorities[i].weight = 0;
            dns->authorities[i].port = 0;
            dns->authorities[i].target = NULL;
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

        for (int i = 0; i < dns->header.ar_count; i++) {
            dns->additionals[i].name = NULL;
            dns->additionals[i].type = 0;
            dns->additionals[i].a_class = 0;
            dns->additionals[i].ttl = 0;
            dns->additionals[i].rdlength = 0;
            dns->additionals[i].rdata = NULL;

            dns->additionals[i].mname = NULL;
            dns->additionals[i].rname = NULL;
            dns->additionals[i].serial_number = 0;
            dns->additionals[i].refresh_interval = 0;
            dns->additionals[i].retry_interval = 0;
            dns->additionals[i].expire_limit = 0;
            dns->additionals[i].minimum_ttl = 0;

            dns->additionals[i].preference = 0;
            dns->additionals[i].mail_exchange = NULL;

            dns->additionals[i].priority = 0;
            dns->additionals[i].weight = 0;
            dns->additionals[i].port = 0;
            dns->additionals[i].target = NULL;
        }

        support_resource_record_parser(&reader, dns->additionals, dns->header.ar_count, packet);
    }



}

void verbose_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    char time_str[64];
    struct tm *ltime;
    time_t local_tv_sec = pkthdr->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);

    struct ip *ip_header;
    struct ip6_hdr *ipv6_header;
    const struct udphdr *udp_header;
    dns_packet dns;

    char src_ip[INET6_ADDRSTRLEN]; 
    char dst_ip[INET6_ADDRSTRLEN]; 

    uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));
    uint16_t src_port, dst_port; 

   if (ethertype == 0x0800) { 
        ip_header = (struct ip *)(packet + 14); 

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4); 
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
    } else if (ethertype == 0x86dd) { // IPv6
        ipv6_header = (struct ip6_hdr *)(packet + 14);

        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        udp_header = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr)); 
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
    } else {
        printf("Unsupported packet type\n");
        return;
    }


    support_dns_packet_parser(packet, &dns);

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
            case 33:
                record_type = "SRV";
                break;
            default:
                record_type = "UNKNOWN";
                break;
        }
        if(strcmp(record_type, "UNKNOWN") != 0) {
            printf("%s %s %s\n", dns.questions[i].qname, class_to_string(dns.questions[i].qclass), record_type);
        } else {
            printf("UNKNOWN TYPE\n");
        }
    }

    if (dns.header.an_count > 0) {
        printf("\n[Answer Section]\n");
        for (int i = 0; i < dns.header.an_count; i++) {
            print_resource_record(&dns.answers[i]);
        }
    }

    if (dns.header.ns_count > 0) {
        printf("\n[Authority Section]\n");
        for (int i = 0; i < dns.header.ns_count; i++) {
            print_resource_record(&dns.authorities[i]);
        }
    }

    if (dns.header.ar_count > 0) {
        printf("\n[Additional Section]\n");
        for (int i = 0; i < dns.header.ar_count; i++) {
            print_resource_record(&dns.additionals[i]);
        }
    }

    


    printf("====================\n");
    printf("\n");
    free_dns_packet(&dns);

}



void non_verbose_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    char time_str[64];
    struct tm *ltime;
    time_t local_tv_sec = pkthdr->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);

    struct ip *ip_header;
    struct ip6_hdr *ipv6_header;
    const struct udphdr *udp_header;
    dns_packet dns;

    char src_ip[INET6_ADDRSTRLEN]; 
    char dst_ip[INET6_ADDRSTRLEN]; 

    uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));

   if (ethertype == 0x0800) { 
        ip_header = (struct ip *)(packet + 14); 

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4); 
    } else if (ethertype == 0x86dd) { // IPv6
        ipv6_header = (struct ip6_hdr *)(packet + 14);

        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        udp_header = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr)); 
    
    } else {
        printf("Ethertype: 0x%04x\n", ethertype);
        printf("Unsupported packet type\n");
        return;
    }
    

    support_dns_packet_parser(packet, &dns);

   // Convert from network byte order to host byte order
    uint16_t flags = dns.header.flags;
    uint8_t qr;
    if ((flags & 0x8000) != 0) { 
        qr = 'R'; 
    } else {
        qr = 'Q';
    }


   printf("%s %s -> %s (", time_str, src_ip, dst_ip);
   printf("%c %d/%u/%u/%u)\n",
           qr,          
           dns.header.q_count,          
           dns.header.an_count,            
           dns.header.ns_count,         
           dns.header.ar_count);      

    free_dns_packet(&dns);
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

    pcap_freecode(&fp);
    return handle;
}


void start_packet_capture(Arguments *arguments) {

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "udp port 53";
    bpf_u_int32 net = 0;

    if(arguments->domain_file != NULL) {
        hash_table_domain = create_hash_table();
    }   

    if(arguments->translation_file != NULL) {
        hash_table_domain_ip_combined = create_hash_table();
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
            
            signal(SIGINT, handle_signal);
            while(!stop_capture) {
                if(arguments->verbose == 1)  {
                    pcap_loop(handle, 0, verbose_packet_handler, NULL);
                } else {
                    pcap_loop(handle, 0, non_verbose_packet_handler, NULL);
                }
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
        write_domains_to_file(hash_table_domain, arguments->domain_file); 
        free_hash_table(hash_table_domain);
    }

    if(arguments->translation_file) {
        write_domains_to_file(hash_table_domain_ip_combined, arguments->translation_file);
        free_hash_table(hash_table_domain_ip_combined);
    }

}
