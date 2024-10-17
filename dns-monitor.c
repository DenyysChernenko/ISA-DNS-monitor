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

    start_packet_capture(arguments);

    free(arguments);
    return EXIT_SUCCESS;
}