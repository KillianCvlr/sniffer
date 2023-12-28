
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>

#include "headers.h"
#include "packet_parser.h"
#include "args.h"


char errbuf[PCAP_ERRBUF_SIZE];

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header){
    printf("NEW PACKET :\n");
    printf("Timestamp : %d:%d\n", packet_header.ts.tv_sec, packet_header.ts.tv_usec);
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

    // Find a device
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        printf("Error finding device: %s\n", errbuf);
        return 1;
    }

    // Afficher le nom de l'interface par défaut
    printf("Listening on standard device : %s\n", device);

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            errbuf
        );

     /* Attempt to capture one packet. If there is no network traffic
      and the timeout is reached, it will return NULL */
    printf("Capturing Packet... \n\n");
    packet = pcap_next(handle, &packet_header);
    if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    } else {
        printf("Jacked a packet with length of [%d]\n", packet_header.len);
        /* Our function to output some info */
        print_packet_info(packet, packet_header);
        parse_ethernet(packet, options.verbose, 0);
    }

    /* Quitting*/
    pcap_close(handle);
    closeOption(&options);
    return 0;
}