#include "args.h"

void printUsage(void){
    printf("Usage : sudo ./bin/sniffer <options\n"
    "Options disponibles : \n"
    "\t -i <iterface> : Interface à utiliser pour la capture de packet\n"
    "\t -o <fichier> : Fichier à lire pour l'analyse de trames\n"
    "\t -f <filtre> : Filtre à utiliser pendant l'analyse des trames\n"
    "\t -v <1|2|3> : Verbosité de l'analyse (1 = concis, 2 = synthétique, 3 = complet)\n"
    "\t -n <nb_paquet> : Nombre de paquets à analyser\n");
}


void initOption(options_t *options){
    options->input = 0;
    options->verbose = -1;
    options->filtre = 0;
    options->bpf = NULL;
    options->inputFilename = NULL;
    options->inputFile = NULL;
    options->device = NULL;
    options->protocol = NULL;
    options->nb_packet = -1;
}

void parseArgs(int argc, char **argv, options_t *options){
    initOption(options);

    int c;
    while((c = getopt(argc, argv, "hi:f:o:v:p:n:")) != -1){
        switch(c){
        case 'h':
            printUsage();
            exit(1);

        case 'i':
            options->input = INPUT_DEVICE;
            options->device = optarg;
            break;

        case 'f':
            options->filtre = 1;
            options->bpf = optarg;
            break;

        case 'o':
            options->input = INPUT_FILE;
            options->inputFilename = optarg;
            options->inputFile = fopen(optarg, "r");
            break;

        case 'v':
            options->verbose = atoi(optarg);
            break;

        case 'p':
            options->protocol = optarg;
            break;

        case 'n':
            options->nb_packet = atoi(optarg);
            break;

        case '?':
            if (optopt == 'o' || optopt == 'v' || optopt == 'i' ||
                optopt == 'f' || optopt == 'p' || optopt == 'n')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else {
                options->input = INPUT_UNKNOWN;
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            printUsage();
            abort();
        default:
            printUsage();
            abort();
        }

    }
}

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

void checkOption(options_t *options){
    if (options->input == INPUT_UNKNOWN) {
        fprintf(stderr, "Pas d'entrée pour la capture spécifiée\n"
        "Capture sur l'entrée par défaut ! \n"
        "Voici une liste des différentes interfaces disponibles :\n");
        print_all_devs();
        options->input = INPUT_DEFAULT;
    }

    if (options->inputFilename == NULL && options->input == INPUT_FILE) {
        fprintf(stderr, "Veuillez saisir le fichier à lire (.pcap)\n");
        exit(1);
    }

    if (options->inputFilename == NULL && options->input == INPUT_FILE) {
        fprintf(stderr, "Veuillez saisir le fichier à lire (.pcap)\n");
        exit(1);
    }

    if (options->inputFile == NULL && options->input == INPUT_FILE) {
        fprintf(stderr, "Echec à l'ouverture du fichier\n");
        exit(1);
    }

    if (options->verbose == -1) {
        fprintf(stderr, "Niveau de verbosité par défaut (3)\n");
        options->verbose = 3;
    }

    if (options->verbose <= 0 || options->verbose > 3) {
        fprintf(stderr, "Niveau de verbosité doit être entre 1 et 3 inclus\n");
        exit(1);
    }
}

void closeOption(options_t *options){
    if (options->inputFile) fclose(options->inputFile);
}
