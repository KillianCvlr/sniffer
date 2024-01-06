#include "protocols/telnet.h"

void parse_telnet(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "TELNET" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        if(size){
            if (packet[0] == TELNET_IAC) {
                PRINT_TREE(prof, "IAC \n");
                switch (packet[1]) {
                case TELNET_WILL:
                    PRINT_TREE(prof, "WILL \n");
                    break;
                case TELNET_WONT:
                    PRINT_TREE(prof, "WONT \n");
                    break;
                case TELNET_DO:
                    PRINT_TREE(prof, "DO \n");
                    break;
                case TELNET_DONT:
                    PRINT_TREE(prof, "DONT \n");
                    break;
                case TELNET_SB:
                    PRINT_TREE(prof, "SB \n");
                    break;
                case TELNET_GA:
                    PRINT_TREE(prof, "GA \n");
                    break;
                case TELNET_EL:
                    PRINT_TREE(prof, "EL \n");
                    break;
                case TELNET_EC:
                    PRINT_TREE(prof, "EC \n");
                    break;
                case TELNET_AYT:
                    PRINT_TREE(prof, "AYT \n");
                    break;
                case TELNET_AO:
                    PRINT_TREE(prof, "AO \n");
                    break;
                case TELNET_IP:
                    PRINT_TREE(prof, "IP \n");
                    break;
                case TELNET_BREAK:
                    PRINT_TREE(prof, "BREAK \n");
                    break;
                case TELNET_DM:
                    PRINT_TREE(prof, "DM \n");
                    break;
                case TELNET_NOP:
                    PRINT_TREE(prof, "NOP \n");
                    break;
                case TELNET_SE:
                    PRINT_TREE(prof, "SE \n");
                    break;
                default:
                    PRINT_TREE(prof, "UNKNOWN \n");
                    break;
                }
                switch (packet[2]) {
                case TELNET_BINARY:
                    PRINT_TREE(prof, "BINARY \n");
                    break;
                case TELNET_ECHO:
                    PRINT_TREE(prof, "ECHO \n");
                    break;
                case TELNET_RECONNECTION:
                    PRINT_TREE(prof, "RECONNECTION \n");
                    break;
                case TELNET_SUPPRESS_GO_AHEAD:
                    PRINT_TREE(prof, "SUPPRESS GO AHEAD \n");
                    break;
                case TELNET_APPROX_MESSAGE_SIZE_NEGOTIATION:
                    PRINT_TREE(prof, "APPROX MESSAGE SIZE NEGOTIATION \n");
                    break;
                case TELNET_STATUS:
                    PRINT_TREE(prof, "STATUS \n");
                    break;
                case TELNET_TIMING_MARK:
                    PRINT_TREE(prof, "TIMING MARK \n");
                    break;
                case TELNET_RCTE:
                    PRINT_TREE(prof, "REMOTE CONTROLLED TRANSMISSION AND ECHOING \n");
                    break;
                case TELNET_OLW:
                    PRINT_TREE(prof, "OUTPUT LINE WIDTH \n");
                    break;
                case TELNET_OPS:
                    PRINT_TREE(prof, "OUTPUT PAGE SIZE \n");
                    break;
                case TELNET_OCRD:
                    PRINT_TREE(prof, "OUTPUT CARRIAGE RETURN DISPOSITION \n");
                    break;
                case TELNET_OHTS:
                    PRINT_TREE(prof, "OUTPUT HORIZONTAL TAB STOPS \n");
                    break;
                case TELNET_OHTD:
                    PRINT_TREE(prof, "OUTPUT HORIZONTAL TAB DISPOSITION \n");
                    break;
                case TELNET_OFD:
                    PRINT_TREE(prof, "OUTPUT FORMFEED DISPOSITION \n");
                    break;
                case TELNET_OVT:
                    PRINT_TREE(prof, "OUTPUT VERTICAL TABSTOPS \n");
                    break;
                case TELNET_OVTD:
                    PRINT_TREE(prof, "OUTPUT VERTICAL TAB DISPOSITION \n");
                    break;
                case TELNET_OLFD:
                    PRINT_TREE(prof, "OUTPUT LINEFEED DISPOSITION \n");
                    break;
                case TELNET_EXTEND_ASCII:
                    PRINT_TREE(prof, "EXTENDED ASCII \n");
                    break;
                case TELNET_LOGOUT:
                    PRINT_TREE(prof, "LOGOUT \n");
                    break;
                case TELNET_BYTE_MACRO:
                    PRINT_TREE(prof, "BYTE MACRO \n");
                    break;
                case TELNET_DATA_ENTRY_TERMINAL:
                    PRINT_TREE(prof, "DATA ENTRY TERMINAL \n");
                    break;  
                case TELNET_SUPDUP:
                    PRINT_TREE(prof, "SUPDUP \n");
                    break;
                case TELNET_SUPDUP_OUTPUT:
                    PRINT_TREE(prof, "SUPDUP OUTPUT \n");
                    break;
                case TELNET_SEND_LOCATION:
                    PRINT_TREE(prof, "SEND LOCATION \n");
                    break;
                case TELNET_TERMINAL_TYPE:
                    PRINT_TREE(prof, "TERMINAL TYPE \n");
                    break;
                case TELNET_END_OF_RECORD:
                    PRINT_TREE(prof, "END OF RECORD \n");
                    break;
                case TELNET_TUID:
                    PRINT_TREE(prof, "TUID \n");
                    break;
                case TELNET_OUTMRK:
                    PRINT_TREE(prof, "OUTPUT MARKING \n");
                    break;
                case TELNET_TTYLOC:
                    PRINT_TREE(prof, "TTYLOC \n");
                    break;
                case TELNET_3270_REGIME:
                    PRINT_TREE(prof, "3270 REGIME \n");
                    break;
                case TELNET_X3_PAD:
                    PRINT_TREE(prof, "X3 PAD \n");
                    break;
                case TELNET_NAWS:
                    PRINT_TREE(prof, "NAWS \n");
                    break;
                case TELNET_TERMINAL_SPEED:
                    PRINT_TREE(prof, "TERMINAL SPEED \n");
                    break;
                case TELNET_TOGGLE_FLOW_CONTROL:
                    PRINT_TREE(prof, "TOGGLE FLOW CONTROL \n");
                    break;
                case TELNET_LINEMODE:
                    PRINT_TREE(prof, "LINEMODE \n");
                    break;
                case TELNET_X_DISPLAY_LOCATION:
                    PRINT_TREE(prof, "X DISPLAY LOCATION \n");
                    break;
                case TELNET_OLD_ENVIRONMENT_VARIABLES:
                    PRINT_TREE(prof, "OLD ENVIRONMENT VARIABLES \n");
                    break;
                case TELNET_AUTHENTICATION:
                    PRINT_TREE(prof, "AUTHENTICATION \n");
                    break;
                case TELNET_ENCRYPTION:
                    PRINT_TREE(prof, "ENCRYPTION \n");
                    break;
                case TELNET_NEW_ENVIRONMENT_VARIABLES:
                    PRINT_TREE(prof, "NEW ENVIRONMENT VARIABLES \n");
                    break;
                case TELNET_TN3270E:
                    PRINT_TREE(prof, "TN3270E \n");
                    break;
                case TELNET_XAUTH:
                    PRINT_TREE(prof, "XAUTH \n");
                    break;
                case TELNET_CHARSET:
                    PRINT_TREE(prof, "CHARSET \n");
                    break;  
                case TELNET_REMOTE_SERIAL_PORT:
                    PRINT_TREE(prof, "REMOTE SERIAL PORT \n");
                    break;
                case TELNET_COM_PORT_CONTROL:
                    PRINT_TREE(prof, "COM PORT CONTROL \n");
                    break;
                case TELNET_SUPPRESS_LOCAL_ECHO:
                    PRINT_TREE(prof, "SUPPRESS LOCAL ECHO \n");
                    break;
                case TELNET_START_TLS:
                    PRINT_TREE(prof, "START TLS \n");
                    break;
                case TELNET_KERMIT:
                    PRINT_TREE(prof, "KERMIT \n");
                    break;
                case TELNET_SEND_URL:
                    PRINT_TREE(prof, "SEND URL \n");
                    break;
                case TELNET_FORWARD_X:
                    PRINT_TREE(prof, "FORWARD X \n");
                    break;
                case TELNET_PRAGMA_LOGON:
                    PRINT_TREE(prof, "PRAGMA LOGON \n");
                    break;
                case TELNET_SSPI_LOGON:
                    PRINT_TREE(prof, "SSPI LOGON \n");
                    break;
                case TELNET_PRAGMA_HEARTBEAT:
                    PRINT_TREE(prof, "PRAGMA HEARTBEAT \n");
                    break;
                case TELNET_EXOPL:
                    PRINT_TREE(prof, "EXOPL \n");
                    break;
                default:
                    PRINT_TREE(prof, "UNKNOWN \n");
                    break;
                }
                printf("\n");
            } else {
                print_content(prof, verbose, size, packet);
            }
        }
    }
}