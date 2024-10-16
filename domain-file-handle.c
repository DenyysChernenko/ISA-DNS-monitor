#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "domain-file-handle.h"




unsigned long djb2_hash(const char *domain) {
    unsigned long hash = 5381;
    int c;

    while ((c = *domain++)) {
        hash = ((hash << 5) + hash) + c; 
    }

    return hash;
}


Hash_Domain_Table *create_hash_table() {
    Hash_Domain_Table *hash_table = malloc(sizeof(Hash_Domain_Table));
    if(hash_table == NULL) {
        fprintf(stderr, "Failed to allocate memory for hash table\n");
        exit(EXIT_FAILURE);
    }

    hash_table->table = malloc(sizeof(Domain_Item *) * HASH_TABLE_SIZE);
    if(hash_table->table == NULL) {

        fprintf(stderr, "Failed to allocate memory for hash table itemsss\n");
        free(hash_table);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        hash_table->table[i] = NULL; 
    }
    hash_table->size = HASH_TABLE_SIZE;
    return hash_table;
}


bool insert_domain_into_hashtable(Hash_Domain_Table *hash_table, const char *domain_name) {

    if (hash_table == NULL || domain_name == NULL) {
        fprintf(stderr, "Debug print: Either hash table NULL or domain name NULL\n");
        return false;
    }



    unsigned long index = djb2_hash(domain_name);
    // Made to be in bounds in hash_table
    unsigned long hash_index = index % hash_table->size;
    Domain_Item *current_item = hash_table->table[hash_index];


    // Check for the duplicate domain name
    while (current_item != NULL) {
        if (strcmp(current_item->domain_name, domain_name) == 0) {
            return false; 
        }
        current_item = current_item->next;
    }


    Domain_Item *new_domain_name = malloc(sizeof(Domain_Item));
    if(new_domain_name == NULL) {
        fprintf(stderr, "Failed to allocate memory to new domain name strucutre\n");
        exit(EXIT_FAILURE);
    }

    new_domain_name->domain_name = malloc(strlen(domain_name) + 1);
    if(new_domain_name->domain_name == NULL) {
        fprintf(stderr, "Failed to allocate memory to new domain name strnig\n");
        free(new_domain_name);
        exit(EXIT_FAILURE);
    } 


    strcpy(new_domain_name->domain_name, domain_name);
    new_domain_name->next = hash_table->table[hash_index];
    hash_table->table[hash_index] = new_domain_name; 

    return true; 
}

bool write_domains_to_file(Hash_Domain_Table *hash_table, const char *file_name) {
    if (hash_table == NULL || file_name == NULL) {
        fprintf(stderr, "Failed to allocate memory for hash table\n");
        return false;
    }

    FILE *file = fopen(file_name, "w");
    if (file == NULL) {
        fprintf(stderr, "Debug print: Either hash table NULL or domain name NULL\n");
        return false;
    }

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        Domain_Item *current_item = hash_table->table[i];

        while (current_item != NULL) {
            fprintf(file, "%s\n", current_item->domain_name);  
            current_item = current_item->next;  
        }
    }

    fclose(file);  
    return true;   
}