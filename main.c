/**
 * stm32w-wireshark - a command line utility to read packet capture
 * from the USB dongle supplied with the STMicroelectronics 
 * STM32-RFCKIT running their Wireshark server firmware.
 *
 *
 *
 * Copyright (c) 2012, Joe Desbonnet, jdesbonnet@gmail.com
 * Copyright (c) 2015, Raphaël Doursenaud, rdoursenaud@free.fr
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * The name of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>


#define APP_NAME "stm32w-wireshark"
#define VERSION "0.2a"

#define TRUE 1
#define FALSE 0

// Define error codes used internally
const static int ERR_INVALID_CHANNEL = -60;
const static int ERR_INVALID_ADDRESS = -61;
const static int ERR_TIMEOUT = -62;

// Output formats
const static int FORMAT_PCAP = 1;
const static int FORMAT_HEX = 2;

// PCAP constants
const static int PCAP_MAGIC = 0xa1b2c3d4;
const static short PCAP_VERSION_MAJOR = 2;
const static short PCAP_VERSION_MINOR = 4;
const static int PCAP_TZ = 0;                // thiszone: GMT to local correction
const static int PCAP_SIGFIGS = 0;            // sigfigs: accuracy of timestamps
const static int PCAP_SNAPLEN = 128;        // snaplen: max len of packets, in octets
const static int PCAP_LINKTYPE = 0xc3;        // data link type DLT_IEEE802_15_4 (see <pcap/bpf.h>)

// The debug level set with the -d command line switch
int debug_level = 0;


// Use -q flag to enable quiet mode. Warning messages will be suppressed.
int quiet_mode = FALSE;

// Set to true in signal_handler to signal exit from main loop
int exit_flag = FALSE;

void debug(int level, const char *msg, ...);

void warning(const char *msg, ...);


/**
 * Open serial IO device to STM32W-RFCKIT dongle. 
 * (8N1, 57600bps, raw mode, no handshaking)
 *
 * @param deviceName Pointer to string with device name (eg "/dev/ttyACM0")
 * @return Operating system file descriptor or -1 if there was an error.
 */
int stm32w_open(char *deviceName) {

    int fd = open(deviceName, O_RDWR);
    if (fd == 0) {
        fprintf(stderr, "Error: unable to open device %s\n", deviceName);
        return -1;
    }

    struct termios tios;
    int status = tcgetattr(fd, &tios);
    if (status < 0) {
        fprintf(stderr, "Error: error calling tcgetattr\n");
        return -1;
    }

    // Set tx/rx speed at 115200bps, and set raw mode
    cfsetispeed(&tios, B115200);
    cfsetospeed(&tios, B115200);
    cfmakeraw(&tios);

    tios.c_cflag &= ~CSTOPB; // Set 1 stop bit
    tios.c_cflag |= (CREAD | CLOCAL); // Enable receiver and disable hardware flow control
    tios.c_oflag = 0; // Disable some modem settings


    //tios.c_cc[VMIN] = 1;
    //tios.c_cc[VTIME] = 0;

    tcsetattr(fd, TCSANOW, &tios);

    return fd;
}

/**
 * Close serial IO device.
 * @param fd File descriptor
 */
void stm32w_close(int fd) {
    close(fd);
}

/**
 * Calculate checksum. Checksum is the bitwise NOT of the arithemetic sum of 
 * the frame (excluding the 0x15 0xFF prefix, but including the length field).
 * @param buf Pointer to start of frame (ie the length field)
 * @param len Length of frame (length field, command field + data)
 * @return 8 bit frame checksum 
 */
int stm32w_checksum(uint8_t *buf, int len) {
    int sum = 0;
    uint8_t *end = buf + len;
    while (buf < end) {
        sum += *buf++;
    }
    return (~sum) & 0xff;
}


/**
 * Display to stderr current version of this application.
 */
void version() {
    fprintf(stderr, "%s, version %s\n", APP_NAME, VERSION);
}

/**
 * Display help and usage information. 
 */
void usage() {
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: stm32w-wireshark [-q] [-v] [-h] [-d level] [-f format] device channel\n");

    //fprintf (stderr,"  -c channel \t Set channel. Allowed values: 11 to 26.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d level \t Set debug level, 0 = min (default), 9 = max verbosity\n");
    fprintf(stderr, "  -f format \t Output format: pcap (default) | hex \n");
    fprintf(stderr, "  -q \t\t Quiet mode: suppress warning messages.\n");
    fprintf(stderr, "  -v \t\t Print version to stderr and exit\n");
    fprintf(stderr, "  -h \t\t Display this message to stderr and exit\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Parameters:\n");
    fprintf(stderr, "  device:  the unix device file corresponding to the dongle device (often /dev/ttyACM0)\n");
    fprintf(stderr, "  channel: the 802.15.4 channel. Allowed values from 11 to 26.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "See this blog post for details: \n");
    fprintf(stderr, "  http://jdesbonnet.blogspot.com/2012/04/stm32w-rfckit-as-802154-network.html\n");
    fprintf(stderr, "Version: ");
    version();
    fprintf(stderr, "Authors:\n");
    fprintf(stderr, "  Joe Desbonnet, jdesbonnet@gmail.com.\n");
    fprintf(stderr, "  Raphaël Doursenaud, rdoursenaud@free.fr\n");
    fprintf(stderr, "Copyright 2012-2015. Source released under BSD licence.\n");
    fprintf(stderr, "\n");
}


/**
 * Display debug message if suitable log level is selected. 
 * Use vararg mechanism to allow use similar to the fprintf()
 * function.
 *
 * @param level Display this message if log level is greater
 * or equal this level. Otherwise ignore the message.
 * @param msg  Format string as described in fprintf()
 */
void debug(int level, const char *msg, ...) {
    if (level >= debug_level) {
        return;
    }
    va_list args;
    va_start(args, msg);        // args after 'msg' are unknown
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(args);
}

/**
 * Display warning message if unless quiet_mode is enabled.
 * 
 * @param msg  Format string as described in fprintf()
 */
void warning(const char *msg, ...) {
    if (quiet_mode) {
        return;
    }
    fprintf(stderr, "WARNING: ");
    va_list args;
    va_start(args, msg);        // args after 'msg' are unknown
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(args);
}

/**
 * Signal handler for handling SIGPIPE and...
 */
void signal_handler(int signum, siginfo_t *info, void *ptr) {
    debug(1, "Received signal %d originating from PID %lu\n", signum, (unsigned long) info->si_pid);
    //exit(EXIT_SUCCESS);
    exit_flag = TRUE;
}

/**
 * Continue to read from file handle fd until 'length' bytes
 * have been read.
 */
void read_n_bytes(int fd, uint8_t *buf, int length) {
    int n = 0;
    while (n < length) {
        n += read(fd, buf + n, length - n);
    }
}

/**
 * Display length bytes from pointer buf in zero padded
 * hex.
 */
void display_hex(uint8_t *buf, int length) {
    int i;
    for (i = 0; i < length; i++) {
        fprintf(stderr, "%02X ", buf[i]);
    }
}


/**
 * Read a frame from the STM32W-RFCKIT USB dongle. The frame 
 * is copied into buf. It includes the 0x15 0xFF prefix,
 * the checksum and 0x0C terminator.
 * If the checksum does not match with the computed value an
 * error code is returned.
 *
 * @return The entire frame length (including prefix 0x15 0xFF
 * and 0x0C terminator) if successful, -1 on error.
 */
int stm32w_read_frame(int fd, uint8_t *buf) {

    // Look for start of frame (0x15, 0xFF)
    while (1) {
        read_n_bytes(fd, buf, 2);
        if ((buf[0] == 0x15) && (buf[1] == 0xFF)) {
            break;
        }
    }

    // Read frame length field. This value includes the length field
    // but excludes the checksum and terminator (0x0C). Therefore
    // +1 to arrive at the remaining bytes left to be read in the
    // current frame
    read_n_bytes(fd, buf + 2, 1);
    int frame_length = *(buf + 2);

    // Read frame into buf starting at index 3
    // (index 0,1,2 occupied by 0x15, 0xFF, frame length field)
    read_n_bytes(fd, buf + 3, frame_length + 1);

    // Calculate frame checksum (frame length + data)
    int cksum = stm32w_checksum(buf + 2, frame_length);


    if (buf[2 + frame_length + 1] != 0x0C) {
        warning("expecting 0x0C frame terminator, but got %02X", buf[2 + frame_length + 1]);
    }

    return (cksum == buf[2 + frame_length]) ? frame_length + 4 : -1;
}


int main(int argc, char **argv) {

    int channel = 12;
    int output_format = FORMAT_PCAP;
    char *device;

    // Setup signal handler. Catching SIGPIPE allows for exit when
    // piping to Wireshark for live packet feed.
    //signal(SIGPIPE, signal_handler);
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = signal_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGPIPE, &act, NULL);


    // Parse command line arguments. See usage() for details.
    int c;
    while ((c = getopt(argc, argv, "c:d:f:hqs:t:v")) != -1) {
        switch (c) {

            /*
            case 'c':
                channel = atoi (optarg);
                if (channel < 11 || channel > 26) {
                    fprintf (stderr, "Invalid channel. Must be in range 11 to 26. Use -h for help.\n");
                    exit(-1);
                }
                break;
            */
            case 'd':
                debug_level = atoi(optarg);
                break;

            case 'f':
                if (strncmp("pcap", optarg, 4) == 0) {
                    output_format = FORMAT_PCAP;
                } else if (strncmp("hex", optarg, 3) == 0) {
                    output_format = FORMAT_HEX;
                }
                break;

            case 'h':
                version();
                usage();
                exit(EXIT_SUCCESS);

            case 'q':
                quiet_mode = TRUE;
                break;

            case 'v':
                version();
                exit(EXIT_SUCCESS);
            case '?':    // case when a command line switch argument is missing
                /*
                if (optopt == 'c') {
                    fprintf (stderr,"ERROR: 802.15.4 channel 11 to 26 must be specified with -c\n");
                    exit(-1);
                }
                */
                if (optopt == 'd') {
                    fprintf(stderr, "ERROR: debug level 0 .. 9 must be specified with -d\n");
                    exit(-1);
                }
                break;
        }
    }

    // Two parameters are mandatory
    if (argc - optind < 2) {
        fprintf(stderr, "Error: missing command arguments.\n");
        version();
        usage();
        exit(EXIT_FAILURE);
    }

    device = argv[optind];
    channel = atoi(argv[optind + 1]);

    if (channel < 11 || channel > 26) {
        fprintf(stderr, "Error: invalid channel. Must be in range 11 to 26. Use -h for help.\n");
        exit(EXIT_FAILURE);
    }

    if (debug_level > 0) {
        debug(1, "device=%s", device);
        debug(1, "channel=%d", channel);
    }

    if (debug_level > 0) {
        fprintf(stderr, "DEBUG: debug level %d\n", debug_level);
    }


    int n;


    // Get start time of capture. Won't worry about subsecond resolution for this.
    struct timespec tp;

    // Open dongle device
    int fd = stm32w_open(device);
    if (fd < 1) {
        fprintf(stderr, "Error: unable to open device %s\n", device);
        return EXIT_FAILURE;
    }


    // Ignore anything aleady in the buffer
    tcflush(fd, TCIFLUSH);

    // Buffer for frame storage
    uint8_t buf[262];

    // Command 0x10: set channel
    buf[0] = 0x15;
    buf[1] = 0xFF;
    buf[2] = 0x03; // Len
    buf[3] = 0x10; // Set Channel command
    buf[4] = channel;
    buf[5] = stm32w_checksum(buf + 2, 3);
    buf[6] = 0x0C;
    fprintf(stderr, "Writing command 0x10 (set channel), ");
    write(fd, buf, 7);
    // Read response. Expect 15 FF 03 90 channel cksum 0C
    n = stm32w_read_frame(fd, buf);
    //fprintf (stderr,"response: n=%d ",n);
    //display_hex (buf,n);
    //fprintf (stderr,"\n");

    // Command 0x11: sniff mode on
    buf[0] = 0x15;
    buf[1] = 0xFF;
    buf[2] = 0x02;
    buf[3] = 0x11;
    buf[4] = stm32w_checksum(buf + 2, 2);
    buf[5] = 0x0C;
    fprintf(stderr, "Writing command 0x11 (start sniffing), ");
    write(fd, buf, 6);
    // Read response. Expect 15 FF ?? 91 ?? ?? cksum 0C
    n = stm32w_read_frame(fd, buf);
    //fprintf (stderr,"response: n=%d ",n);
    //display_hex (buf,n);
    //fprintf (stderr,"\n");



    // Write PCAP header
    if (output_format == FORMAT_PCAP) {
        fwrite(&PCAP_MAGIC, sizeof(int), 1, stdout);
        fwrite(&PCAP_VERSION_MAJOR, sizeof(short), 1, stdout);
        fwrite(&PCAP_VERSION_MINOR, sizeof(short), 1, stdout);
        fwrite(&PCAP_TZ, sizeof(int), 1, stdout);                // thiszone: GMT to local correction
        fwrite(&PCAP_SIGFIGS, sizeof(int), 1, stdout);            // sigfigs: accuracy of timestamps
        fwrite(&PCAP_SNAPLEN, sizeof(int), 1, stdout);            // snaplen: max len of packets, in octets
        fwrite(&PCAP_LINKTYPE, sizeof(int), 1, stdout);        // data link type
        fflush(stdout);
    }


    int frame_length;
    uint32_t stm32w_time;
    uint32_t stm32w_time_sec;
    uint32_t stm32w_time_usec;
    uint64_t stm32w_time_full;
    uint32_t host_ts_sec;
    uint32_t host_ts_usec;
    uint64_t host_ts_full;

    int delta;

    int ncapture = 0;


    clock_gettime(CLOCK_REALTIME, &tp);
    long host_start_sec = tp.tv_sec;


    while (1) {

        // Frame is the entire from from the dongle including 0x15, 0xFF preamble,
        // length field, 0xF0 command, 802.15.4 packet metadata and actual packet
        // 802.15.4 FCS, dongle frame checksum and 0x0C terminator.
        frame_length = stm32w_read_frame(fd, buf);

        if (frame_length < 0) {
            fprintf(stderr, "Warning: bad frame\n");
            continue;
        }

        // Write frame (excluding 0x15, 0xFF prefix, checksum and 0x0C)
        if (output_format == FORMAT_HEX) {
            display_hex(buf, frame_length);
            fprintf(stderr, "\n");
        }

        // Is this a frame type 0xF0?
        if (buf[3] != 0xF0) {
            fprintf(stderr, "Warning: unexpected frame type %02X\n", buf[3]);
            continue;
        }

        // Get host time of packet reception
        // TODO: might be better to capture time at start of frame
        clock_gettime(CLOCK_REALTIME, &tp);
        host_ts_sec = tp.tv_sec;
        host_ts_usec = tp.tv_nsec / 1000;

        /*
        fprintf (stderr, "\nstm32w_time: ");
        display_hex(buf+4,5);
        fprintf (stderr,"\n");
        stm32w_time =  *( (uint32_t*)(buf+4));
        stm32w_time_usec = (10000* (stm32w_time & 0x000fffff)) / 0xfffff;
        stm32w_time_usec *= 100;
        stm32w_time =  *( (uint32_t*)(buf+6));
        stm32w_time_sec = (stm32w_time&0xffffff) >> 4;
        stm32w_time_full = (long)stm32w_time_sec*1000000L + stm32w_time_usec;
        host_ts_full = (long)(host_ts_sec-host_start_sec)*1000000L + (long)host_ts_usec;
        delta = (int)(stm32w_time_full - host_ts_full);
        delta =  stm32w_time_sec - (host_ts_sec - host_start_sec);
        fprintf (stdout,"host_sec=%d ",host_ts_sec);
        fprintf (stdout,"host_usec=%d ",host_ts_usec);
        fprintf (stdout,"stm32w_sec=%d ", stm32w_time_sec);
        fprintf (stdout,"stm32w_usec=%d ", stm32w_time_usec);
        fprintf (stdout,"delta=%d ", delta);
        //fprintf (stdout," %d %d %d\n", buf[2],buf[8],buf[data_length-1],buf[data_length]);
        fprintf (stdout,"\n");
        fflush (stdout);
        */

        // Remaining code applies to PCAP format only
        if (output_format != FORMAT_PCAP) {
            //continue;
        }


        ncapture++;

        fwrite(&host_ts_sec, sizeof(int), 1, stdout);    // ts_sec: timestamp seconds
        fwrite(&host_ts_usec, sizeof(int), 1, stdout);    // ts_usec: timestamp microseconds

        // 802.15.4 packet length including 2 bytes FCS
        int f802154length = frame_length - 13;
        fwrite(&f802154length, sizeof(uint32_t), 1, stdout);
        fwrite(&f802154length, sizeof(uint32_t), 1, stdout);
        fwrite(buf + 11, 1, f802154length, stdout);
        fflush(stdout);
    }


    stm32w_close(fd);

    debug(1, "Normal exit");
    return EXIT_SUCCESS;
}
