#include <stdio.h>
#include <stdlib.h>
#include "arguments-parse.h"
#include "packet-capture.h"
#include "domain-file-handle.h"
#include <unistd.h>


int main(int argc, char *argv[]) {


    Arguments *arguments = arguments_parsing(argc, argv);

    if(arguments == NULL) {
        fprintf(stderr, "Failed to parse arguments\n");
        return EXIT_FAILURE;
    }

    if(arguments->domain_file != NULL) {
        FILE *file = fopen(arguments->domain_file, "w");
        if(file != NULL) {
            fclose(file);
            printf("Debugging print: Domain file exists: %s\n", arguments->domain_file);
        } 
    }

    if(arguments->translation_file != NULL) {
        FILE *translate_file = fopen(arguments->translation_file, "w");
        if(translate_file != NULL) {
            fclose(translate_file);
            printf("Debbuging print: Translate file exists: %s\n", arguments->translation_file);
        }
    }

    start_packet_capture(arguments);

    free(arguments);
    return EXIT_SUCCESS;
}