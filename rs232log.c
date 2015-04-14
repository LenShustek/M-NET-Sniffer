/*************************************************************************

.      Mitsubishi M-NET sniffer program

Program to receive and decode in realtime the packets that Mitsubishi
heating and air conditioning units use to communicate with each other
and control devices like thermostats.

We monitor the received data of two RS-232 serial ports simultaneously:

(1) M-NET communications, via the home-built M-NET to RS232 adapter
The packets are in binary and are decoded as best we know how.

(2) Control4-to-CoolMaster communcations, via a home-built RS323 sniffer
cable that sends data going in both directions to our serial port receive
data line. The packets are in ASCII and are simply displayed as is.

We expect there to be no simultaneous transmissions, or else the display
and possibly the decoding will get mightly messed up.

This is a command-line (non-GUI) program that runs from a CMD box.
It has been tested under Windows 7 and Windows XP.

The program writes to log.txt as well as the console.

If M-NET communications is being simulated for testing,
 it reads ASCII hex from a text file called serial.dat

The optional command-line parameter -Un causes M-NET packets that not
to or from unit n to be ignored.

--------------------------------------------------------------------------
*   (C) Copyright 2015, Len Shustek
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of version 3 of the GNU General Public License as
*   published by the Free Software Foundation at http://www.gnu.org/licenses,
*   with Additional Permissions under term 7(b) that the original copyright
*   notice and author attibution must be preserved and under term 7(c) that
*   modified versions be marked as different from the original.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
--------------------------------------------------------------------------

Change log

28 Mar 2015,  L. Shustek,  first version
11 Apr 2015,  L. Shustek,  v1.1

**************************************************************************/

// N.B.: Using the lcc "Reformat" command on this file will make the packet
//       format decoder initialization structure look *really* ugly!


#define VERSION "1.1"

#define MNET 1   		// monitor M-NET communications? (else read from file)
#define COOLMASTER 1	// monitor CoolMaster communications?
#define COOLMASTER_KB 0	// simulate CoolMaster using keyboard and loopback plug?

#define coolmaster_com_port 4	// Coolmaster RS232 port COMn (usu. 4)
#define mnet_com_port 5   		//    M-NET   RS232 port COMn (usu. 5)

#define timeout 10  	// M-NET RS232 timeout in milliseconds

#define MAX_DATA 20		// maximum M-NET packet data
#define COOLMASTER_ADDR 0xfb

#define ACK 0x06	// ASCII acknowledge
#define NAK 0x21	// ASCII negative acknowledge

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <conio.h>
#include <sys\timeb.h>
#include <process.h>

union packet_t {
    unsigned char rawdata[MAX_DATA+4+2];
    struct {
        unsigned char cmdrsp;  // 0xBD cmd, 0xBE rsp, 0x3D ??
        unsigned char from_addr;
        unsigned char to_addr;
        unsigned char unk1;  // x3F or 0x7F
        unsigned char data_length;
        unsigned char data[MAX_DATA]; // data bytes
        // followed by: checksum, then ack (0x06) from destination
    };
}
packet;
int raw_datacount = 0;
unsigned char crc = 0;
unsigned char prev_from_addr = 0, prev_to_addr = 0;
int filter_unit = -1;  // unit to filter for; -1 is none

HANDLE handle_mnet = INVALID_HANDLE_VALUE;
HANDLE handle_coolmaster = INVALID_HANDLE_VALUE;
DCB dcbSerialParams = {
    0};
COMMTIMEOUTS timeouts = {
    0};

bool mnet_active = false, coolmaster_active = false;
bool skipping_packet = false;  // malformed: wait for pause to restart
bool filtering_packet = false; // failed unit filter
char dev_name[80];
FILE *logfile, *testfile;
struct _timeb start_time;  // long time; unsigned short millitm;
bool did_newline = true;
static char blanks[]="                                                                       ";

void SayUsage (char *programname) {
    printf("RS232log: M-NET sniffer\n");
}


int HandleOptions(int argc,char *argv[]) {
    /* returns the index of the first argument that is not an option; i.e.
    does not start with a dash or a slash*/

    int i,firstnonoption=0;

    /* --- The following skeleton comes from C:\lcc\lib\wizard\textmode.tpl. */
    for (i=1; i< argc;i++) {
        if (argv[i][0] == '/' || argv[i][0] == '-') {
            switch (toupper(argv[i][1])) {
            case 'H':
            case '?':
                SayUsage(argv[0]);
                exit(1);
            case 'U':  // filter for unit n
                if (sscanf(&argv[i][2],"%d",&filter_unit) != 1) goto opterror;
                printf("Filtering for unit %d\n", filter_unit);
                break;
            /* add more  option switches here */
opterror:
            default:
                fprintf(stderr,"unknown option: %s\n",argv[i]);
                SayUsage(argv[0]);
                exit(4);
            }
        }
        else {
            firstnonoption = i;
            break;
        }
    }
    return firstnonoption;
}

unsigned long delta_time (void) {
    unsigned long delta;
    struct _timeb time_now;
    _ftime(&time_now);
    delta = 1000 * (time_now.time - start_time.time);
    if (time_now.millitm >= start_time.millitm) delta += time_now.millitm - start_time.millitm;
    else
        delta -= start_time.millitm - time_now.millitm;
    start_time = time_now;
    return delta;
}

void close_handle (HANDLE *h, char *msg) {
    if (*h != INVALID_HANDLE_VALUE) {
        fprintf(stderr, "\nClosing %s serial port...", msg);
        if (CloseHandle(*h) == 0)fprintf(stderr, "Error\n");
        else fprintf(stderr, "OK\n");
        *h = INVALID_HANDLE_VALUE;
    }
}

void Cleanup(void) {
    close_handle (&handle_mnet, "M-NET");
    close_handle (&handle_coolmaster, "CoolMaster");
    fclose(stdout);
    fclose(logfile);
}

void exit_msg(const char* err) {
    fprintf(stderr, "%s\n", err);
    Cleanup();
    exit(99);
}

void output (char *fmt, ...) {
    va_list args;
    va_start(args,fmt);
    vfprintf(stdout, fmt, args);
    vfprintf(logfile, fmt, args);
    va_end(args);
}

void newline (void) {
    output ("\n");
    did_newline = true;
    raw_datacount = 0;
    crc = 0;
}

void showtime(unsigned long delta) {
    if (did_newline) {
        if (COOLMASTER) output("%.*s", 27, blanks);  // indent to separate from CoolMaster output
        output ("%5ld.%03d  ", delta/1000,delta%1000);
        did_newline = false;
    }
}

void print_addr (int addr) {
    if (addr == COOLMASTER_ADDR) output("CM");
    else output("%02X", addr);
}

// detailed command decodes

void showtemp (int pos) {
    output(" %d.%d deg C", packet.data[pos]*10+(packet.data[pos+1]>>4), packet.data[pos+1]&0xf);
    float degc = packet.data[pos]*10+(packet.data[pos+1]>>4)+(packet.data[pos+1]&0xf)/10;
    output(", %.1f deg F", degc*9/5+32);
}
void showfanspeed (int pos) {
    int parm = packet.data[pos];
    output(parm==4?" low":parm==5?" medium":parm==6?" high":parm==0x0b?" auto":"???");
}

void poweron (void) {
    int parm = packet.data[2];
    output("turn %s", parm==1?"on":parm==0?"off":"??");
}
void poweron_ack (void) {
    output(" ok");
}
void getstatus (void) {
    output("get status");
}
void getstatus_ack (void) {
    int parm = packet.data[2];
    output(parm==0?" stopped":parm==1?" running":"???");
}
void getmode (void) {
    output("get mode");
}
void getmode_ack (void) {
    int parm = packet.data[2];
    output(parm==7?" heat":parm==8?" cool":"???");
}
void getsetpoint (void) {
    output("get setpoint temp");
};
void getsetpoint_ack (void) {
    showtemp(2);
}
void getfanspeed (void) {
    output("get fan speed");
}
void getfanspeed_ack (void) {
    showfanspeed(2);
}
void setfanspeed (void) {
    output("set fan speed");
    showfanspeed(2);
}
void setfanspeed_ack (void) {
        output(" ok");
}
void getcurrenttemp (void) {
    output ("get current temp");
}
void getcurrenttemp_ack (void) {
    showtemp(3);
}
void setmode (void) {
    int parm = packet.data[2];
    output("set mode %s", parm==7?"heat":parm==8?"cool":parm==32?"auto":"???");
}
void setmode_ack (void) {
    output(" ok");
}
void settemp (void) {
    output("set temp ");
    showtemp(2);
}
void settemp_ack (void) {
    output(" ok");
}


static struct {  //*****  packet format matching table
        #define MAX_CMDSIZE 6 // max bytes we match to decode packet format, starting with data_length
        unsigned char mask[MAX_CMDSIZE];  // mask to AND each byte with
        unsigned char val[MAX_CMDSIZE];   // value to then compare with
        void (*fct) (void);
    } pkt_formats[] = {
        #define M 0xff // complete match mask
        {{M,M,M},   {5,0x0d,0x01}, 		poweron},
        {{M,M,M,M}, {3,0x0d,0x81,0x00}, poweron_ack},
        {{M,M,M},   {3,0x0d,0x02},      setmode},
        {{M,M,M,M}, {3,0x0d,0x82,0x00}, setmode_ack},
        {{M,M,M},   {5,0x05,0x01},      settemp},
        {{M,M,M,M}, {3,0x05,0x81,0x00}, settemp_ack},
        {{M,M,M},   {3,0x0d,0x0e},      setfanspeed},
        {{M,M,M,M}, {3,0x0d,0x8e,0x00}, setfanspeed_ack},
        {{M,M,M},   {2,0x2d,0x01},      getstatus},
        {{M,M,M},   {5,0x2d,0x81},      getstatus_ack},
        {{M,M,M},   {2,0x2d,0x02},      getmode},
        {{M,M,M},   {3,0x2d,0x82},      getmode_ack},
        {{M,M,M},   {2,0x25,0x01},      getsetpoint},
        {{M,M,M},   {5,0x25,0x81},      getsetpoint_ack},
        {{M,M,M},   {2,0x2d,0x0e},      getfanspeed},
        {{M,M,M},   {3,0x2d,0x8e},      getfanspeed_ack},
        {{M,M,M,M}, {3,0x35,0x03,0x22}, getcurrenttemp},
        {{M,M,M,M}, {5,0x35,0x83,0x22}, getcurrenttemp_ack},
        {{0}, 		{0}, 				NULL} // end of table
        };

void decode_packet (void) {
    packet.data_length = min(16,packet.data_length);
    output("%.*s", 18-3*packet.data_length, blanks); // space out to a fixed column

    // format the to and from addresses
    if (packet.from_addr == prev_to_addr && packet.to_addr == prev_from_addr) output("  ");
    else print_addr(packet.from_addr);
    output ("->");
    print_addr(packet.to_addr);
    output(" ");

    for (int fmt=0; ; ++fmt) {  // search for matching packet format
        if (pkt_formats[fmt].fct == NULL) { // end of list: no match
            output("???");  // unknown format
            break;
        }
        for (int i=0; i<MAX_CMDSIZE; ++i) { // try to match all bytes
        if ((packet.rawdata[4+i] & pkt_formats[fmt].mask[i]) != pkt_formats[fmt].val[i]) goto next;
        }
        (pkt_formats[fmt].fct)();  // we matched this template: call the detailed command decode
        break;
next:;
    }

    newline();
    prev_from_addr = packet.from_addr;
    prev_to_addr = packet.to_addr;
}


int main(int argc,char *argv[]){
    unsigned char c;
    DWORD bytes_read, bytes_written;
    unsigned long delta=0;

    #define CM_MAX 80	// CoolMaster character buffer
    unsigned char cm_buf[CM_MAX+1];
    int cm_bufcnt=0;

    #define MN_MAX 80	// M-Net character buffer
    unsigned char mn_buf[MN_MAX+1];
    int mn_bufcnt=0;

    printf("Mitsubishi M-NET Sniffer, version " VERSION "\n");
    HandleOptions(argc,argv);

#if MNET
    // Open serial port for sniffing M-NET
    // This is a simplex contention-based protocol, and we monitor only received data.

    sprintf(dev_name, "\\\\.\\COM%d", mnet_com_port);
    fprintf(stderr, "Opening M-NET on %s...", dev_name);
    handle_mnet = CreateFile(dev_name, GENERIC_READ, 0, 0,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (handle_mnet!=INVALID_HANDLE_VALUE) {
        dcbSerialParams.BaudRate = 9600;
        dcbSerialParams.ByteSize = 8;
        dcbSerialParams.StopBits = ONESTOPBIT;
        dcbSerialParams.Parity = EVENPARITY;
        if(SetCommState(handle_mnet, &dcbSerialParams) == 0) exit_msg("Error setting M-NET port parameters");
        // At 9600 baud, 8 bits, even parity, 1 stop, each character take 1.15 msec
        timeouts.ReadIntervalTimeout = MAXDWORD; // poll only; no wait timeout; // msec
        timeouts.ReadTotalTimeoutConstant = 0; // timeout; // msec
        timeouts.ReadTotalTimeoutMultiplier = 0; // timeout; // msec
        timeouts.WriteTotalTimeoutConstant = 50;
        timeouts.WriteTotalTimeoutMultiplier = 10;
        if(SetCommTimeouts(handle_mnet, &timeouts) == 0) exit_msg("Error setting M-NET serial port timeouts");
        fprintf(stderr,"OK\n");
        mnet_active = true;
    }
    else fprintf(stderr,"Failed\n");
#endif

#if COOLMASTER
    // Open serial port for sniffing between Coolmaster and Control4
    // This is bidirectional half duplex; we monitor received data that has been ORed together in the custom cable.

    sprintf(dev_name, "\\\\.\\COM%d", coolmaster_com_port);
    fprintf(stderr, "Opening Coolmaster/Control4 on %s...", dev_name);
    handle_coolmaster = CreateFile(dev_name, GENERIC_READ|GENERIC_WRITE, 0, 0,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (handle_coolmaster!=INVALID_HANDLE_VALUE) {
        dcbSerialParams.BaudRate = 9600;
        dcbSerialParams.ByteSize = 8;
        dcbSerialParams.StopBits = ONESTOPBIT;
        dcbSerialParams.Parity = NOPARITY;
        if(SetCommState(handle_coolmaster, &dcbSerialParams) == 0) exit_msg("Error setting CoolMaster port parameters");
        // At 9600 baud, 8 bits, no parity, 1 stop, each character take 1.04 msec
        timeouts.ReadIntervalTimeout = MAXDWORD; // poll only; no wait
        timeouts.ReadTotalTimeoutConstant = 0;
        timeouts.ReadTotalTimeoutMultiplier = 0;
        timeouts.WriteTotalTimeoutConstant = 50;
        timeouts.WriteTotalTimeoutMultiplier = 10;
        if(SetCommTimeouts(handle_coolmaster, &timeouts) == 0) exit_msg("Error setting CoolMaster port timeouts");
        fprintf(stderr,"OK\n");
        coolmaster_active = true;
    }
    else fprintf(stderr,"Failed\n");
#endif

#if MNET
    if (!mnet_active && !coolmaster_active) exit_msg ("Neither serial port is open");
#endif

    if ((logfile = fopen("log.txt","a")) == NULL) exit_msg("log.txt open failed");
    fprintf(logfile,"\n");

#if !MNET
    if ((testfile = fopen("serial.dat","r")) == NULL) exit_msg("serial.dat open failed");
#endif

    atexit(Cleanup);
    _ftime(&start_time);

    printf("starting...\n");
    while(1) {

        if(COOLMASTER_KB && coolmaster_active) {
        // simulate CoolMaster traffic from keyboard using RS232 loopback plug
            if (kbhit()) {
                unsigned char ch=getch();
                if (ch == 0x1a) exit_msg("^Z");
                WriteFile(handle_coolmaster, &ch, 1, &bytes_written, 0);
            }
        }

        if (COOLMASTER && coolmaster_active) { // read CoolMaster traffic
            ReadFile(handle_coolmaster, &c, 1, &bytes_read, NULL); // read from CoolMaster RS232 com port, no delay
            if (bytes_read == 1) {
                if (c!=0x0d) { // ignore CR
                    if (cm_bufcnt < CM_MAX) cm_buf[cm_bufcnt++] = c;
                    if (c==0x0a) { // ends with CR/LF
                        cm_buf[cm_bufcnt] = '\0';
                        if (cm_bufcnt > 2) // ignore null or almost null lines
                            output("%s",cm_buf);
                        cm_bufcnt=0;
                    }
                }
            }
        }

        if (!MNET) { // read M-NET traffic from a file
            int val;
            // sleep(1000/20); // msec: slow to 20 cps for testing
            bytes_read = fscanf(testfile, "%2x", &val);
            if (bytes_read == EOF) exit_msg("endfile");
            c = (unsigned char) val;
        }
        else ReadFile(handle_mnet, &c, 1, &bytes_read, NULL); // read from M-NET RS232 com port

        if (bytes_read == 1) {  // another byte came in
            crc += c;
            if (raw_datacount < MAX_DATA) packet.rawdata[raw_datacount++] = c;
            else if (!skipping_packet) {
                printf("***too much data ");
                skipping_packet = true;
            }
            if (!skipping_packet && raw_datacount == 4) { // just finished header: do filters
                if (filter_unit==-1 || ((packet.from_addr == filter_unit) || (packet.to_addr == filter_unit))) {
                    delta = delta_time(); // will display this packet: remember the time
                }
                else filtering_packet = true;
            }
            if (!skipping_packet && raw_datacount >= 5) { // we've read the header and are reading data
                if (raw_datacount == 6+packet.data_length) { // this should be checksum
                    if (crc != 0) {
                        output("*** bad CRC *** ");
                        for (int i=0; i<raw_datacount; ++i) output("%02X ", packet.rawdata[i]);
                        output("\n");
                        skipping_packet = true;
                        crc = 0;
                    }
                }
                if (raw_datacount == 7+packet.data_length) { // this should be ACK or NACK
                    if (!filtering_packet) {
                        // print the packet all at once to avoid interspersing with CoolMaster commands
                            showtime(delta);
                            for (int i=0; i<raw_datacount; ++i) output("%02X ", packet.rawdata[i]);
                            decode_packet();
                        }
                    filtering_packet = false;
                    crc = 0;
                    raw_datacount = 0;
                    if (c == NAK) output("*** Received NAK\n");
                    else if (c != ACK) {  // use this byte as the first byte of the next packet
                        output("Missing ACK or NAK\n");
                        packet.rawdata[0] = c;
                        raw_datacount = 1;
                        crc = c;
                    }
                }
            }
        }
        else { //  start a new line and a new packet after a long time delay
            if (!did_newline) {
                newline();
                showtime(delta_time());
                newline();
                skipping_packet = false;
            }
        }
#if !COOLMASTER_KB
        if (kbhit()) {
            fprintf(stderr,"\nInterrupted...\n");
            return 0;
        }
#endif
    }

    return 0;
}

