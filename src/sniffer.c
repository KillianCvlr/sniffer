#include "headers.h"
#include "args.h"


char errbuf[PCAP_ERRBUF_SIZE];

void print_packet_info(struct pcap_pkthdr packet_header){
    printf("\n");
    printf(BWHT "Packet capture length: " WHT "%d\n", packet_header.caplen);
    printf(BWHT "Packet total length: " WHT "%d\n", packet_header.len);
    printf(BWHT "Packet timestamp: " WHT"%s", ctime((const time_t *)&packet_header.ts.tv_sec));   
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    static int packet_id = 1;
    int verbose = args[0];

    if (verbose >= 3) print_packet_info(*header);

    printf( BHRED "%d ", packet_id);
    parse_ethernet((const u_char *)packet, verbose, 0);
    printf("\n");
    packet_id++;
}



int main(int argc, char *argv[]) {

    //Options de l'utilisateur
    options_t options;
    
    printf(YEL "Options initialisation... \n");
    initOption(&options);
    printf("Option parsing... \n");
    parseArgs(argc, argv, &options);
    printf("Options checking... \n");
    checkOption(&options);
    
    char *device;
    pcap_if_t *alldevsp;
    pcap_t *handle;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    //Setup of the interface
    if (options.input == INPUT_DEFAULT) {
       char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
            printf("Error finding device: %s\n", errbuf);
            return 1;
        }
        device = alldevsp->name;
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
    printf("Capturing Packets... \n\n");
    pcap_loop(handle, options.nb_packet, got_packet, (u_char *)&options.verbose);

    /* Quitting*/
    if(options.input == INPUT_DEFAULT) pcap_freealldevs(alldevsp);
    pcap_close(handle);
    closeOption(&options);
    return 0;
}

