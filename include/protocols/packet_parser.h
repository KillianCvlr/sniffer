#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H
#include "headers.h"
#include "tool.h"
#include <stdio.h>
#include <pcap.h>



void parse_ftp(const u_char *packet, int verbose, int prof, int size);
void parse_smtp(const u_char *packet, int verbose, int prof, int size);
void parse_imap(const u_char *packet, int verbose, int prof, int size);
void options_imap(const u_char *packet_arg, char * buff);
void parse_telnet(const u_char *packet, int verbose, int prof, int size);
void parse_pop3(const u_char *packet, int verbose, int prof, int size);

#endif // PACKET_PARSER_H