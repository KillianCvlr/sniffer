#ifndef H_HEADERS
#define H_HEADERS

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/ip_icmp.h>

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/*	Entetes utilisées ********************************************************/

// Structure de l'en-tete BOOTP
struct bootp_header {
    uint8_t op;          // Type d'opération (1 pour demande, 2 pour réponse)
    uint8_t htype;       // Type de matériel (1 pour Ethernet)
    uint8_t hlen;        // Longueur de l'adresse matérielle (6 pour une adresse MAC Ethernet)
    uint8_t hops;        // Nombre de relais intermédiaires
    uint32_t xid;        // Identifiant d'échange
    uint16_t secs;       // Durée depuis le début de l'opération
    uint16_t flags;      // Flags spéciaux
    uint8_t ciaddr[4];   // Adresse IP client
    uint8_t yiaddr[4];   // Adresse IP attribuée
    uint8_t siaddr[4];   // Adresse IP du serveur d'amorçage
    uint8_t giaddr[4];   // Adresse IP de l'agent de relais
    uint8_t chaddr[16];  // Adresse matérielle client (MAC)
    uint8_t sname[64];   // Nom du serveur d'amorçage
    uint8_t file[128];   // Nom du fichier d'amorçage
    uint32_t magic;      // Signature magique (0x63825363)
    uint8_t options[64]; // Options spécifiques BOOTP/DHCP
};

// Structure de l'en-tete DHCP
struct dhcp_header {
    uint8_t op;          // Type d'opération (1 pour demande, 2 pour réponse)
    uint8_t htype;       // Type de matériel (1 pour Ethernet)
    uint8_t hlen;        // Longueur de l'adresse matérielle (6 pour une adresse MAC Ethernet)
    uint8_t hops;        // Nombre de relais intermédiaires
    uint32_t xid;        // Identifiant d'échange
    uint16_t secs;       // Durée depuis le début de l'opération
    uint16_t flags;      // Flags spéciaux
    uint8_t ciaddr[4];   // Adresse IP client
    uint8_t yiaddr[4];   // Adresse IP attribuée
    uint8_t siaddr[4];   // Adresse IP du serveur d'amorçage
    uint8_t giaddr[4];   // Adresse IP de l'agent de relais
    uint8_t chaddr[16];  // Adresse matérielle client (MAC)
    uint8_t sname[64];   // Nom du serveur d'amorçage
    uint8_t file[128];   // Nom du fichier d'amorçage
    uint32_t magic;      // Signature magique (0x63825363)
    uint8_t options[64]; // Options spécifiques BOOTP/DHCP
};

// Structure de l'en-tete DNS
struct dns_header {
    uint16_t id;          // Identifiant de la requête
    uint16_t flags;       // Drapeaux (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qdcount;     // Nombre de questions dans la section Question
    uint16_t ancount;     // Nombre d'entrées dans la section Réponse
    uint16_t nscount;     // Nombre d'entrées dans la section Autorité
    uint16_t arcount;
};

// Structure de l'en-tete HTTP
struct http_header {
    // Ligne de requête (request line) pour une requête HTTP
    char method[10];       // Méthode HTTP (GET, POST, etc.)
    char uri[256];         // URI de la ressource demandée
    char version[10];      // Version HTTP (HTTP/1.0, HTTP/1.1, etc.)

    // Ligne de statut (status line) pour une réponse HTTP
    uint16_t status_code;  // Code d'état HTTP (200 OK, 404 Not Found, etc.)
    char reason_phrase[256];// Raison de l'état HTTP (OK, Not Found, etc.)

    // En-têtes HTTP
    char headers[1024];     // En-têtes HTTP (champ générique pour les en-têtes)

    // Corps du message (payload)
    char body[4096];        // Corps du message (champ générique pour le corps)
};

// Structure de l'en-tete FTP
struct ftp_header {
    // Commande FTP
    char command[10];       // Commande FTP (USER, PASS, LIST, RETR, etc.)

    // Argument de la commande FTP
    char argument[256];     // Argument de la commande FTP

    // Paramètres FTP supplémentaires
    char params[512];       // Paramètres FTP supplémentaires

    // Réponse FTP
    uint16_t code;          // Code de réponse FTP (ex: 200, 404, etc.)
    char response[256];      // Message de réponse FTP
};

// Structure de l'en-tete SMTP
struct smtp_header {
    // Commande SMTP
    char command[10];       // Commande SMTP (EHLO, HELO, MAIL, RCPT, etc.)

    // Argument de la commande SMTP
    char argument[256];     // Argument de la commande SMTP

    // Paramètres SMTP supplémentaires
    char params[512];       // Paramètres SMTP supplémentaires

    // Réponse SMTP
    uint16_t code;          // Code de réponse SMTP (ex: 220, 500, etc.)
    char response[256];      // Message de réponse SMTP
};

#endif