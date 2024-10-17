#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define HASH_TABLE_SIZE 512
#define MAX_DOMAIN_LENGTH 256

#ifndef DOMAIN_FILE_HANDLE_H
#define DOMAIN_FILE_HANDLE_H

// Domain Item struct (pointer to next, and domain name itself)
typedef struct Domain_Item {
    char *domain_name;
    struct Domain_Item *next; 
} Domain_Item;


// hash domain table, to handle unique domain items 
typedef struct Hash_Domain_Table {
    Domain_Item **table; 
    size_t size;
} Hash_Domain_Table;



/**
 * @brief Hashes a domain name using the djb2 algorithm
 * @param domain domain name string to be hashed
 * @return An hashed value of the domain name
 */
unsigned long djb2_hash(const char *domain);


/**
 * @brief Creates and initializes a new hash table
 * @return A pointer to the newly created Hash_Domain_Table structure, NULL if allocations fails
 */
Hash_Domain_Table *create_hash_table();

/**
 * @brief Inserts a domain name into the hash table
 * 
 * This function adds a domain name to the hash table. If the domain name 
 * already exists in the table, it skipped
 * 
 * @param hash_table Hash_Domain_Table where the domain name will be inserted
 * @param domain_name domain name string to be inserted
 * @return true if the domain name was successfully added, false if it already exists or if an error occurred
 */
bool insert_domain_into_hashtable(Hash_Domain_Table *hash_table, const char *domain_name);

/**
 * @brief Inserts a domain name with it's IPv4/IPv6 into the hash table
 * 
 * This function adds a domain name with it's ip as one string, to the hash table. If the domain name 
 * already exists in the table, it skipped
 * 
 * @param hash_table Hash_Domain_Table where the domain name will be inserted
 * @param domain_name domain name string to be inserted
 * @param ip_address ip, related to domain name
 * @return true if the domain name was successfully added, false if it already exists or if an error occurred
 */
bool insert_domain_ip_into_hashtable(Hash_Domain_Table *hash_table, const char *domain_name, const char *ip_address);


/**
 * @brief Writes all unique domain names from the hash table to a file
 * 
 * This function iterates through the hash table and writes each unique 
 * domain name to the specified file in format -> one line one domain name
 *
 * @param hash_table Hash_Domain_Table containing the domain names to be written to the file
 * @param file_name name of the file
 * @return true if the operation is successful, false if an error occurs
 */
bool write_domains_to_file(Hash_Domain_Table *hash_table, const char *file_name);

#endif