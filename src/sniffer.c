
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>

#include "headers.h"
#include "packet_parser.h"
#include "args.h"


char errbuf[PCAP_ERRBUF_SIZE];

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header){
    printf("\nNEW PACKET :\n");
    printf("Timestamp : %ld:%ld\n", packet_header.ts.tv_sec, packet_header.ts.tv_usec);
    return;    
};

int main(int argc, char **argv[]) {

    //Options de l'utilisateur
    options_t options;
    
    printf("Options initialisation... \n");
    initOption(&options);
    printf("Option parsing... \n");
    parseArgs(argc, argv, &options);
    printf("Options checking... \n");
    checkOption(&options);
    
    char *device;
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    //Setup of the interface
    if (options.input == INPUT_DEFAULT) {
       char errbuf[PCAP_ERRBUF_SIZE];

        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            printf("Error finding device: %s\n", errbuf);
            return 1;
        }

        // Afficher le nom de l'interface par défaut
        printf("Listening on standard device : %s\n", device);
        handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, errbuf);
        if (handle == NULL) {
            printf("%s\n", errbuf);
            return 1;
        }

    } else if (options.input == INPUT_FILE) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_offline(options.inputFilename, errbuf);
        if (handle == NULL) {
            printf("%s\n", errbuf);
            return 1;
        }
        printf("Listening on file : %s\n", options.inputFilename);

    } else if (options.input == INPUT_DEVICE) {

        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(options.device, BUFSIZ, packet_count_limit, timeout_limit, errbuf);
        if (handle == NULL) {
            printf("%s\n", errbuf);
            return 1;
        }
        printf("Listening on device : %s\n", options.device);
    }
    if (options.filter == 1) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, options.bpf, 0, 0) == -1) {
            printf("pcap_compile error\n");
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            printf("pcap_setfilter error\n");
        }
        printf("Listening with filter : %s\n", options.bpf);
    }
    printf("Capturing Packet... \n\n");
    pcap_loop(handle, options.nb_packet, got_packet, (u_char *)&options.verbose);

    /* Quitting*/
    pcap_close(handle);
    closeOption(&options);
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    int verbose = args[0];

    if (verbose >= 2) print_packet_info(packet, *header);

    parse_ethernet((char *)packet, verbose, 0);
    printf("\n");
}