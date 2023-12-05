
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>

//#include "headers.h"
//#include "packet_parser.h"


char errbuf[PCAP_ERRBUF_SIZE];

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header){
    
};

void print_all_devs(){
    pcap_if_t * interfaces;
    
    // Récupérer la liste des interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Erreur en récupérant les interfaces: %s\n", errbuf);
        return;
    }

    // Parcourir la liste des interfaces
    pcap_if_t *interface;
    for (interface = interfaces; interface != NULL; interface = interface->next) {
        printf("Nom: %s\n", interface->name);
        if (interface->description)
            printf("Description: %s\n", interface->description);
        else
            printf("Pas de description disponible\n");
        printf("\n");
    }

    // Libérer la mémoire allouée par pcap_findalldevs
    pcap_freealldevs(interfaces);
}

int main(int argc, char *argv[]) {
    char *device;
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    print_all_devs();

    // Find a device
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        printf("Error finding device: %s\n", errbuf);
        return 1;
    }

    // Afficher le nom de l'interface par défaut
    printf("Interface par défaut: %s\n", device);

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
     packet = pcap_next(handle, &packet_header);
     if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    } else {
        printf("Jacked a packet with length of [%d]\n", packet_header.len);
    }

//     /* Our function to output some info */
//     print_packet_info(packet, packet_header);

    // /* Quitting*/
    // pcap_close(handle);
    return 0;
}