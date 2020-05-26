/****************************************************************************/
/* extractcc - A program to extract data from a covert channel using the    */
/*             TLS protocol                                                 */
/*                                                                          */
/* This program is part of the master thesis "Network covert channels in    */
/* Transport Layer Security protocol and their detection" submitted to      */
/* the FernUniversitaet in Hagen at 2020-02-23                              */
/*                                                                          */
/* Author:  Corinna Heinz <ch@sysv.de>                                      */
/* License: Creative Commons Zero (CC0)                                     */
/****************************************************************************/


#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/signal.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Connection idle timeout in seconds
#define TIMEOUT 300

// TLS record types
enum {
   TLSR_CHANGE_CIPHER_SPEC = 20,
   TLSR_ALERT              = 21,
   TLSR_HANDSHAKE          = 22,
   TLSR_DATA               = 23
};

// The states of our simple state machine
enum {
   STATE_LOOKING = 1,
   STATE_VERIFYING,
   STATE_EXTRACTING,
   STATE_ANALYZE
};

// List of TCP segments
static struct netpkt {
   unsigned int seq, len, off;
   unsigned char *buf;
   struct netpkt *next;
} *netpkts = NULL;

static pcap_t *p; // PCAP handle for packet capturing
static char *prefix = "extract"; // basefile name for writing data files

// Current connection metadata:
static unsigned int clip, srvip;       // client and server ip
static unsigned short clport, srvport; // client and server port
static unsigned int iniseq;       // sequence nr relative to network buffer start
static time_t lastseen;           // last packet seen in this connection
static int timeout = TIMEOUT;     // The current idle timeout of the connection
static int state = STATE_LOOKING; // current state of our state machine
static int verbosity;             // The verbosity level of the program
static int analyze;               // 1 if in analyze mode
static int stats;                 // Show connection stats
static int tcpbytes;              // Number of TCP bytes received

// The pre-shared key between sender and receiver
unsigned int key;
// the master- and channel specific seeds of the current TLS covert channels
unsigned int masterseed;
unsigned int rlseed, ivseed, ctseed;

// Dynamic array for record length encoding
unsigned char *rlenc;
int rlenclen, rlencbuflen, rlencoff;

// Dynamic buffer for iv encoding
unsigned char *ivenc;
int ivenclen, ivencbuflen, ivencoff;

// Dynamic buffer for ct encoding
unsigned char *ctenc;
int ctenclen, ctencbuflen, ctencoff;

// Counter for statistics
int a_time, a_records, a_ccs, a_alert, a_hs, a_data, a_others;

/* function verb(level, format, ...)
 * Print a message if the current verbosity level is equal or greater
 * than the specified level.
 * level   - the minimum verbosity level required
 * format  - a printf-compatible format string
 * ...     - Zero or more format arguments
 */
static void verb (int level, char *format, ...) {
   if (level > verbosity)
      return;
   va_list ap;
   va_start(ap, format);
   vfprintf(stderr, format, ap);
   va_end(ap);
}

/* function timems ()
 * Returns the time in milliseconds since the unix epoch
 * used for benchmarking
 * returns: time in ms since 1970-01-01 00:00:00.000 UTC
 */
int timems (void) {
   struct timeval tv;
   gettimeofday(&tv, NULL);

   return tv.tv_sec*1000+tv.tv_usec/1000;
}

// Signal handler for terminating the extraction program
static void terminate (int sig) {
   verb(0, "Got CTRL+C (%d), terminating...\n", sig);
   fflush(stdout);
   _exit(EXIT_SUCCESS);
}

// Signal handler for timeouts
static void sigalrm (int sig) {
   (void)sig; // disable unused parameter warning
   pcap_breakloop(p);
   alarm(1);
}

/* function tcpseg_state (s)
 * Print the current list of TCP segments
 * s - Caller label to print
 * returns: nothing
 */
void tcpseg_state (char *s) {
   struct netpkt *tmp = netpkts;
   if (!tmp)
      verb(2, "\nTCP Segment List empty! (%s)\n", s);
   else
      verb(2, "\nTCP Segment List (%s):\n", s);
   while (tmp) {
      verb(2, "%5d - %5d (%d bytes)\n", tmp->seq + tmp->off,
           tmp->seq + tmp->len, tmp->len - tmp->off);
      tmp = tmp->next;
   }
}

/* function tcpseg_add (seq, len, p)
 * Add a new tcp segment and merge adjacent buffers
 * seq - The sequence number of the new packet
 * buf - The payload data buffer
 * len - The payload length of the new packet
 */
void tcpseg_add (unsigned int seq, const unsigned char *buf, int len) {
   struct netpkt *cur = netpkts;

   if (len == 0)
      return;

   if (netpkts && seq < netpkts->seq) {
      return;
   }
   // Fast track: The new segment is located at the end of the buffer
   if (netpkts && netpkts->seq + netpkts->len >= seq) {
      int off = netpkts->seq + netpkts->len - seq;
      if (off < 0 || len < off)
         return;
      seq += off;
      buf += off;
      len -= off;
      netpkts->buf = realloc(netpkts->buf, netpkts->len + len);
      memcpy(netpkts->buf+netpkts->len, buf, len);
      netpkts->len += len;
   } else {
      //Create the new packet;
      struct netpkt *n = malloc(sizeof *n);
      n->seq = seq;
      n->len = len;
      n->off = 0;
      n->buf = malloc(len);
      memcpy(n->buf, buf, len);

      // Insert it sorted by initial sequence in the linked list
      if (!netpkts || netpkts->seq > seq) {
         n->next = netpkts;
         netpkts = n;
      } else {
         while (cur->next && cur->next->seq < seq)
            cur = cur->next;
         n->next = cur->next;
         cur->next = n;
      }
   }

   // Now merge following adjacent packets
   while (netpkts->next && netpkts->next->seq <= netpkts->seq + netpkts->len) {
      netpkts->buf = realloc(netpkts->buf,
            netpkts->next->seq - netpkts->seq + netpkts->next->len);
      memcpy(netpkts->buf + (netpkts->next->seq - netpkts->seq),
            netpkts->next->buf, netpkts->next->len);
      netpkts->len = netpkts->next->seq - netpkts->seq + netpkts->next->len;
      struct netpkt * tmp = netpkts->next;
      netpkts->next = netpkts->next->next;
      free(tmp->buf);
      free(tmp);
   }
}

/* function tcpseg_rem (len)
 * Remove already processed tcp data from the list
 * len - The number of bytes to remove
 * returns: nothing
 */
void tcpseg_rem (unsigned int len) {
   assert (len <= netpkts->len);
   if (len == netpkts->len - netpkts->off) {
      netpkts->seq += netpkts->len;
      netpkts->off = 0;
      netpkts->len = 0;
   } else {
      netpkts->off += len;
   }
   tcpbytes += len;
}

/* function tcpseg_free ()
 * Free the list of tcp segments
 * returns: nothing
 */
void tcpseg_free () {
   while (netpkts) {
      struct netpkt *tmp = netpkts;
      netpkts = netpkts->next;
      free(tmp->buf);
      free(tmp);
   }
}


/* function is_tls_hello(payload, paylen) 
 * Checks, if the given payload is a TLS hello message (or at
 * least the begin of a TLS hello message)
 * payload - TCP payload of the packet
 * paylen  - length of the payload
 * returns: 1, if it is a TLS hello packet, 0 otherwise
 */
static int is_tls_hello (const unsigned char *payload, int paylen) {
   if ((paylen >= 11) &&
         (payload[0] == 0x16) &&
         (payload[1] == 0x03) &&
         (payload[2] <= 0x03) &&
         (payload[3] < 0xC0) &&
         (payload[5] == 0x01) &&
         (payload[9] == 0x03) &&
         (payload[10] == 0x02 || payload[10] == 0x03) ) {
      return 1;
   }

   return 0;
}

/* function check_hello()
 * Check, if the "hello" message announces a covert channel in
 * this TLS connection.
 * returns: 1, if a covert channel exists, 0 otherwise
 */
static int check_hello() {
   unsigned char *netbuf = netpkts->buf + netpkts->off;
   int netbuflen = netpkts->len - netpkts->off;

   // The structure of the "hello" packet is:
   //  0 - 5 bytes record header (RFC5246 6.2.1)
   //  5 - 4 bytes handshake message header (RFC5246 7.4)
   //  Client Hello Message:
   //  9 - V V              ( tls major/minor version, RFC5246 7.4.1.2 )
   // 11 - T T T T M M M M  ( 32 bytes Random, RFC5246 7.4.1.2   )
   // 19 - R R R R R R R R  ( this random data is specially      )
   // 27 - R R R R R R R R  ( crafted if a covert channel exists )
   // 35 - R R R R R R R R  ( and is completely random otherwise )
   // ... rest of client hello ...
   //
   // Explanation:
   // V - TLS version
   // T - gmt unix timestamp
   // M - master seed (to generate IV/RL/CT seed)
   // R - Pseudo-random bytes generated from IV seed

   if (netbuflen < 50) {
      // At least 50 bytes are needed for a valid Client Hello
      // message
      return 0;
   }

   // Copy the master seed, which is at the start of the
   // "random bytes" in the TLS hello packet right after the
   // gmt_unix_timestamp (see RFC5246 Section 7.4.1.2)
   memcpy(&masterseed, netbuf+15, 4);
   verb(3, "Using masterseed %08X and key %08X\n", masterseed, key);
   masterseed ^= key;
   // The channel specific seeds are generated from the master seed
   ivseed = rand_r(&masterseed);
   rlseed = rand_r(&masterseed);
   ctseed = rand_r(&masterseed);

   char buf[24];
   for (unsigned int i = 0; i < sizeof(buf); i++) {
      // Generate 24 bytes from the ivseed
      buf[i] = rand_r(&ivseed);
   }
   if (memcmp(netbuf+19, buf, sizeof(buf)) == 0) {
      // 24 bytes of the random data in the hello packet is
      // generated from the ivseed, so we know, that this
      // hello message was specially crafted for a covert
      // channel.
      // Print a diagnostic message that we have found a covert channel
      // in this TLS connection
      struct in_addr in;
      in.s_addr = clip;
      verb(0, "Found TLS covert channel signature in connection %s:%d -> ",
           inet_ntoa(in), htons(clport));
      in.s_addr = srvip;
      verb(0, "%s:%d\n", inet_ntoa(in), htons(srvport));
      return 1; // Signal a covert channel
   } else {
      return 0; // No covert channel in this connection
   }
}

/* function handledata (buf, len, off)
 * Check the buffer for a new line and output it. Advance the
 * offset "off".
 * buf - the buffer
 * len - length of the buffer
 * off - (pointer to) offset into the buffer
 * returns: 1, if a complete message was received, 0 otherwise
 */
static void handledata (unsigned char *buf, int len, int *off) {
   char *chan; // Channel type

   // Determine the channel type for output
   if      (buf == ivenc)
      chan = "IV";
   else if (buf == rlenc)
      chan = "RL";
   else if (buf == ctenc)
      chan = "CT";
   else
      chan = "UK";

   do {
      // Calculate start of new data and length
      unsigned char *ptr = buf + *off, *end;
      int l = len - *off;
      if (l == 0) // No data available
         return;

      switch (*ptr) {
         case 0xf1:
            // We have a "message", look for terminator
            end = memchr(ptr, '\0', l);
            if (!end) // No full message yet
               return;
            // Display message to the receiver
            verb(0, "[%s-MSG ] %s\n", chan, ptr+1);
            // Update the offset
            *off += (end - ptr) + 1;
            break;

         case 0xf2:
            // We have a file
            if (l < 5)
               return;
            // The next four bytes indicate the length of the file
            int size = (ptr[1]<<24)+(ptr[2]<<16)+(ptr[3]<<8)+ptr[4];
            if (l < size+6) // Not the whole file available yet
               return;
            unsigned char *data = ptr + 5;
            unsigned char *fname = data + size;
            end = memchr(fname, '\0', l - size - 5);
            if (!end) // Filename is not available yet
               return;
            // Update the offset into the buffer
            *off += (end - ptr) + 1;
            char f[256]; // Filename buffer
            int nr = 1, fd = -1;
            do {
               // Construct a filename
               snprintf(f, sizeof(f), "%s.%s.%s.%d", prefix, fname, chan, nr++);
               // Try to open the file for writing
               fd = open(f, O_CREAT|O_RDWR|O_EXCL, 0600);
               if (fd < 0 && errno != EEXIST) {
                  // We have an error writing to the file.
                  verb(0, "Error writing file %s: %s\n", f, strerror(errno));
                  return;
               }
            } while (fd < 0);
            // Write out the data
            write(fd, data, size);
            close(fd);
            verb(0, "[%s-FILE] %s (%d bytes)\n", chan, f, size);
            break;
         default:
            // We received a message type that we do not understand.
            verb(0, "Error: Invalid message type %02X\n", *ptr);
            // Update the offset
            off++;
            break;
      }
   } while (1);
}

/* function extract_data_iv (buf, len)
 * Extract IV encoded data. Copy and descramble the given IV
 * into a buffer. Print it, when all IV encoded data was
 * received.
 * buf - The initialization vector (IV)
 * len - length of the IV
 * returns nothing
 */
static void extract_data_iv (unsigned char *buf, int len) {
   for (int i = 0; i < len; i++) {
      // Descramble the data with the negotiated
      // iv encoding seed
      unsigned char x = rand_r(&ivseed);
      // Store the descrambled byte into the buffer
      buf[i] ^= x;
   }
   // Get the length byte
   int l = buf[0];
   // Reallocate the buffer for the new data
   if (ivencbuflen < ivenclen + l + 1) {
      ivencbuflen = ivenclen + l + 1 + 1024;
   }
   ivenc = realloc(ivenc, ivencbuflen);
   // Copy the descrambled data
   memcpy(ivenc+ivenclen, buf+1, l);
   ivenclen += l;
   ivenc[ivenclen] = '\0';
   handledata(ivenc, ivenclen, &ivencoff);
}


/* function extract_data_rl (len)
 * Extract record length encoded data. First, put
 * all record lengths into a dynamic array and decode it, when
 * the required amount of data is reached.
 * len - length of the record
 * returns nothing
 */
static void extract_data_rl (int len) {
   static int nrbits = 0;
   static unsigned char ch = 0;

   if (len < 0) { // Reset
      nrbits = 0;
      ch = 0;
   }

   int bit;
   switch (len) {
      case 64: // 64 bytes is a 0-bit
         bit = 0;
         break;
      case 80: // 80 bytes is a 1-bit
         bit = 1;
         break;
      default: // All other lengths contain no information
         return;
   }

   verb(3, "RLENC: Got %d bit (len %d)\n", bit, len);
   ch |= (bit << nrbits++);
   if (nrbits == 8) {
      if (rlencbuflen < rlenclen + 2) {
         rlencbuflen += 1024;
         rlenc = realloc(rlenc, rlencbuflen);
      }
      rlenc[rlenclen++] = ch^((unsigned char)rand_r(&rlseed));
      rlenc[rlenclen] = 0;
      nrbits = 0;
      ch = 0;
      verb(3, "RLENC: Got byte: %02X\n", rlenc[rlenclen-1]);
      handledata(rlenc, rlenclen, &rlencoff);
   }
}

/* function extract_data_ct (recordtype)
 * Extract content type encoded data bit for bit.
 * An Alert-record is a 0-bit, a Data-record is a
 * 1-bit. Bit-stuffing is performed on every 4th
 * 0-bit to keep OpenSSL happy.
 * recordtype - type of the record
 * returns nothing
 */
static void extract_data_ct (int recordtype) {
   static int nrbits = -1, alerts = 0;
   static unsigned char ch = 0;

   if (recordtype < 0) { // Reset of statemachine requested
      nrbits = -1;
      alerts = 0;
      ch = 0;
   }

   int bit;
   switch (recordtype) {
      case TLSR_DATA:
         if (alerts == 4) { // Bit stuffing, ignore this bit
            alerts = 0;     // Reset stuff counter
            return;
         }
         alerts = 0; // Reset consecutive alerts counter
         if (nrbits < 0)
            return;
         bit = 1;
         break;
      case TLSR_ALERT:
         alerts++;
         bit = 0;
         break;
      default:
         return;
   }
   if (nrbits >= 0) {
      ch |= (bit << nrbits);
   }
   verb(3, "CTENC: Got %d bit\n", bit);
   nrbits++;
   if (nrbits == 8) {
      if (ctencbuflen < ctenclen + 2) {
         ctencbuflen += 1024;
         ctenc = realloc(ctenc, ctencbuflen);
      }
      ctenc[ctenclen++] = ch^((unsigned char)rand_r(&ctseed));
      ctenc[ctenclen] = 0;
      nrbits = -1;
      ch = 0;
      verb(3, "CTENC: Got byte: %02X\n", ctenc[ctenclen-1]);
   }
   handledata(ctenc, ctenclen, &ctencoff);
}

/* function parse_records()
 * Scan the network buffer and parse the next TLS record.
 * For the record structure, see RFC5246 6.2.1
 * returns nothing
 */
int parse_records (void) {
   if (!netpkts)
      return 0;
   unsigned char *netbuf = netpkts->buf + netpkts->off;
   int netbuflen = netpkts->len - netpkts->off;
   if (netbuflen < 5) {
      // Network buffer is too small for a TLS record header,
      // wait for more data
      return 0;
   }
   // Record type is the first byte
   int recordtype = netbuf[0];
   // Decode the record length
   int len = netbuf[3]*256+netbuf[4];
   if (netbuflen < len+5) {
      // We do not have the complete record yet, wait for more
      return 0;
   }
   // We have a complete record now. Update statistics first.
   verb(3, "Got TLS record type %d\n", recordtype);
   a_records++;
   if      (recordtype == TLSR_CHANGE_CIPHER_SPEC) a_ccs++;
   else if (recordtype == TLSR_ALERT             ) a_alert++;
   else if (recordtype == TLSR_HANDSHAKE         ) a_hs++;
   else if (recordtype == TLSR_DATA              ) a_data++;
   else    /*   We got some other record type   */ a_others++;

   if (state == STATE_VERIFYING) {
      // If we are still verifying, look for record type
      // "handshake" and handshake type 1 (client hello)
      if (recordtype == TLSR_HANDSHAKE && netbuf[5] == 1) {
         // Check, if the hello message announces a
         // covert channel
         if (check_hello() == 0) {
            // No covert channel, drop the connection if we are not
            // in analyze mode
            if (!analyze)
               return -1;
            else // we want to analyze the connection
               state = STATE_ANALYZE;
         } else {
            // We are now in state "extracting", in which we
            // retrieve the covert data from the channel
            state = STATE_EXTRACTING;
         }
      }
   } else if (state == STATE_EXTRACTING) {
      // Look for TLS data messages with covert data
      if (recordtype == TLSR_DATA) {
         // Add the packet length to a list for
         // record length encoding
#ifndef RLDISABLED
         extract_data_rl(len);
#endif
         if (len < 21) {
            // If we do not have at least an IV
            // the connection is broken, drop it
            return -2;
         }
         // Extract the data from the IV of the message
         extract_data_iv(netbuf+5, 16);
      }
      extract_data_ct(recordtype);
      if (stats)
         verb(0, "IV: %d, RL: %d, CT: %d, TCP: %d  \r",
              ivenclen, rlenclen, ctenclen, tcpbytes);
   }

   // Remove the record from the network buffer
   tcpseg_rem(len + 5);

   return 1;

}

/* function mystrerror (errno)
 * Translates program-specific error codes into a string
 * errno - Error number
 * returns: Human-readable error string
 */ 
char *mystrerror (int nr) {
   switch (nr) {
      case -1:
         return "No covert channel detected";
         break;
      case -2:
         return "Error extracting IV data";
         break;
      default:
         return "Unexpected error";
   }
}


/* connection_terminated ()
 * The connection was terminated, process the extracted data and
 * reset the state machine.
 * returns: nothing
 */
void connection_terminated () {
   if (state == STATE_EXTRACTING || state == STATE_ANALYZE) {
      verb(0, "Connection terminated.\n");
      verb(1, "IV: %d, RL: %d, CT: %d, TCP: %d\n",
           ivenclen, rlenclen, ctenclen, tcpbytes);
   }
   
   int a_verb = 1;
   if (analyze) {
      a_verb = 0;
   }

   // Print out the statistics
   int avgbpr = tcpbytes/a_records;
   int dtime = timems() - a_time;
   long bps = tcpbytes*1000L/dtime;
   verb(a_verb, "Connection terminated.\n");
   verb(a_verb, "Bytes   total: %6d\n", tcpbytes);
   verb(a_verb, "Records total: %6d\n", a_records);
   verb(a_verb, " -   CCS (20): %6d\n", a_ccs);
   verb(a_verb, " - Alert (21): %6d\n", a_alert);
   verb(a_verb, " -    HS (22): %6d\n", a_hs);
   verb(a_verb, " -  Data (23): %6d\n", a_data);
   verb(a_verb, " - Others    : %6d\n", a_others);
   verb(a_verb, "Avg bytes/rec: %6d\n", avgbpr);
   verb(a_verb, "          bps: %6ld\n", bps);
   verb(a_verb, "\n");
   verb(a_verb, "# bytes, records,   ccs,  alrt,    hs,  data, others,   bpr,   bps\n");
   verb(a_verb, "# %5d, %7d, %5d, %5d, %5d, %5d, %6d, %5d, %5ld\n",
         tcpbytes, a_records, a_ccs, a_alert, a_hs, a_data, a_others, avgbpr, bps);

   // reset the statemachine
   state = STATE_LOOKING;
   // reset the counters
   ivenclen = rlenclen = ctenclen = 0;
   ivencoff = rlencoff = ctencoff = 0;
   // reset the timeout to default
   timeout = TIMEOUT;
   // And clean up (meta-)data from old connections
   tcpseg_free();
   // Reset internal statemachines of the channel extractors
   extract_data_rl(-1);
   extract_data_ct(-1);
   // Reset statistics
   a_time = tcpbytes = a_records = a_ccs = a_alert = a_hs = a_data = a_others = 0;
}

/* function handle_packet (p, l)
 * Called for each packet on the wire
 * p - packet buffer
 * l - buffer length
 */
static void handle_packet (const unsigned char *p, int l) {
   // If we already track a connection (State "Looking"), check if
   // we run into a timeout. Currently, we have a timeout of 3 seconds.
   time_t now = time(NULL);
   if (state != STATE_LOOKING && (now - lastseen > timeout)) {
      verb(1, "Connection timeouted (%ld seconds idle)\n", (now - lastseen));
      connection_terminated();
   }

   if (!p) // No packet
      return;

   // Skip l2 ethernet header
   p += 14;
   l -= 14; 

   if (l < 40) // Minimum ip and tcp header
      return;
   struct iphdr *ip = (struct iphdr *)p;
   if (ip->protocol != IPPROTO_TCP)
      return; // Only look for TCP packets
   int tot_len = ntohs(ip->tot_len);
   if (tot_len > l)
      return; // Short packet
   l = tot_len;

   int ihl = ip->ihl*4; // Calculate TCP header offset
   if (l < ihl+20)
      return; // Remaining packet too small
   struct tcphdr *tcp = (struct tcphdr *) (p + ihl);
   int paylen = l - ihl - tcp->doff*4; // Length of payload
   if (paylen < 0)
      return; // No payload, bail out
   const unsigned char *payload = p + l - paylen; // Payload offset

   // State "Looking" is looking for a new TLS connection
   if (state == STATE_LOOKING) {
      // Check if we have a valid TLS client hello message
      if (is_tls_hello(payload, paylen)) {
         verb(1, "TLS hello detected, tracking connection...\n");
         // If yes, the next state is "verifying" to see,
         // if there is a covert channel
         state = STATE_VERIFYING;
         // Remember client IP and port
         clip = ip->saddr;
         srvip = ip->daddr;
         clport = tcp->source;
         srvport = tcp->dest;
         // As well as the TCP sequence number
         iniseq = ntohl(tcp->seq);
         // Timestamp of the last packet
         lastseen = now;
         a_time = timems();
      }
   }
   if (state == STATE_VERIFYING || state == STATE_EXTRACTING || state == STATE_ANALYZE) {
      // We currently track a connection
      // see if ip and port of the packet matches
      // our tracked connection
      if (clip == ip->saddr && clport == tcp->source) {
         // We saw a TCP rst or fin packet, the
         // connection is terminated
         if (tcp->rst || tcp->fin) {
            // reset state to "looking"
            timeout = 3;
            verb(1, "Connection terminated by %s,"
               " Setting timeout to %d secs \n", tcp->rst?"RST":"FIN", timeout);
            if (tcp->rst)
               return;
         }

         // Sequence of the fragment relative to the connection start
         unsigned int seq = ntohl(tcp->seq) - iniseq;
         // Add the tcp segment to the list
         tcpseg_add(seq, payload, paylen);
         // Update timestamp of last activity for timeouts
         lastseen = now;
         do {
            // Try to parse the next record
            int st = parse_records();
            if (st < 0) {
               // An error occurred, drop the
               // connection
               verb(1, "Connection terminated: Error %d (%s)\n",
                    st, mystrerror(st));
               connection_terminated();
               return;
            } else if (st == 0) {
               // We need more data for the
               // next record
               break;
            }
         } while (1);
      }
   }

}

void usage (void) {
   verb(0,
   "Usage: extractcc [-i <iface>] [-f <filename>] [-s] [-p] [-v] [-a]\n"
   "       -i <iface>    - Listen on specified interface (default: eth0)\n"
   "       -f <filename> - Prefix for extracted data files (default: extract)\n"
   "       -s            - Show live connection stats\n"
   "       -p            - Set promiscuous mode\n"
   "       -a            - Set analyze mode\n"
   "       -v            - Increase verbosity level (multiple)\n"
   "       -k <key>      - A 32-bit integer pre-shared key (default: 0)\n"
   "\n");
   exit(EXIT_FAILURE);
}

/* function main(argc, argv)
 * Main entry point into the progra,
 * argc - Argument count
 * argv - Argument vector
 * returns: exit code
 */
int main (int argc, char **argv) {
   char *iface = "eth0"; // Default interface
   int c, promisc = 0;

   while ((c = getopt (argc, argv, "i:f:k:vspla")) != -1) {
      switch (c) {
         case 'v':
            // Increase verbosity
            verbosity++;
            break;
         case 'i':
            // Set interface
            iface = optarg;
            break;
         case 'p':
            // Set promiscuous mode
            promisc = 1;
            break;
         case 's':
            // Show connection statistics
            stats = 1;
            break;
         case 'a':
            // Set analyze mode
            analyze = 1;
            break;
         case 'k':
            // A pre-shared key to XOR the masterseed with
            key = strtol(optarg, 0, 10);
            break;
         case 'f':
            // Set prefix for filenames for covert data
            prefix = optarg;
            break;
         default:
            usage();
      }
   }

   // Open the interface for packet capturing
   char errbuf[PCAP_ERRBUF_SIZE];
   p = pcap_create(iface, errbuf);
   if (p == NULL) {
      verb(0, "Error opening device %s: %s\n", iface, errbuf);
      exit(EXIT_FAILURE);
   }
   pcap_set_buffer_size(p, 16*1048576);
   pcap_set_immediate_mode(p, 0);
   pcap_set_promisc(p, promisc);
   if (pcap_activate(p)) {
      verb(0, "Error capturing from device %s: %s\n", iface, pcap_geterr(p));
      exit(EXIT_FAILURE);
   }

   // Register a signal handler to support CTRL+C and the timeout
   signal(SIGINT, terminate);
   signal(SIGALRM, sigalrm);
   alarm(1);

   // The main packet read loop
   verb(0, "Listening for TLS connections on interface %s...\n", iface);
   do {
      struct pcap_pkthdr header;
      const unsigned char *packet = pcap_next(p, &header);
      handle_packet((unsigned char *)packet, header.caplen);
   } while (1);

   // Never reached.
   exit(EXIT_SUCCESS);
}


// vim: ts=3:sw=3:et
