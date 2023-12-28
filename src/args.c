#include "args.h"

void printUsage(void){
    printf("Usage : sudo ./bin/sniffer <options\n"
    "Available options : \n"
    "\t -i <device> : Device to listen on\n"
    "\t -o <file> : File to open (.pcap)\n"
    "\t -f <filter> : Filter used during sniffing\n"
    "\t -v <1|2|3> : Verbosity of the output(1 = concise, 2 = synthetic, 3 = complete)\n"
    "\t -n <integer> : Number of packet to analyse\n");
}


void initOption(options_t *options){
    options->input = 0;
    options->verbose = -1;
    options->filter = 0;
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
            options->filter = 1;
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
        fprintf(stderr, "Unable to catch the devices: %s\n", errbuf);
        return;
    }

    // Parcourir la liste des interfaces
    pcap_if_t *interface;
    for (interface = interfaces; interface != NULL; interface = interface->next) {
        printf("Name: %s\n", interface->name);
        if (interface->description)
            printf("| %s\n", interface->description);
        else
            printf("| \n");
        printf("\n");
    }

    // Libérer la mémoire allouée par pcap_findalldevs
    pcap_freealldevs(interfaces);
}

void checkOption(options_t *options){
    if (options->input == INPUT_UNKNOWN) {
        fprintf(stderr, "No Entry for the device to use\n"
        "Here is a list of the different devices to listne to :\n");
        print_all_devs();
        fprintf("Sniffing on the standard device ! \n")
        options->input = INPUT_DEFAULT;
    }

    if (options->inputFilename == NULL && options->input == INPUT_FILE) {
        fprintf(stderr, "Please state a file (.pcap)\n");
        exit(1);
    }


    if (options->inputFile == NULL && options->input == INPUT_FILE) {
        fprintf(stderr, "Unable to open the file\n");
        exit(1);
    }

    if (options->verbose == -1) {
        fprintf(stderr, "Standard verbosity (3 - complete)\n");
        options->verbose = 3;
    }

    if (options->verbose <= 0 || options->verbose > 3) {
        fprintf(stderr, "Verbosity must be between 1 and 3\n");
        exit(1);
    }
}

void closeOption(options_t *options){
    if (options->inputFile) fclose(options->inputFile);
}
