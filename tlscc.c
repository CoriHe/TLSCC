/****************************************************************************/
/* tlscc - A program to transmit data through a covert channel using the    */
/*         TLS protocol                                                     */
/*                                                                          */
/* This program is part of the master thesis "Network covert channels in    */
/* Transport Layer Security protocol and their detection" submitted to      */
/* the FernUniversitaet in Hagen at 2020-02-23                              */
/*                                                                          */
/* Author:  Corinna Heinz <ch@sysv.de>                                      */
/* License: Creative Commons Zero (CC0)                                     */
/****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <netdb.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

// TLS metadata for encryption
unsigned char clientserverrandom[64];
unsigned char premastersecret[48];
unsigned char masterkey[48];
unsigned char client_write_MAC_key[32];
unsigned char server_write_MAC_key[32];
unsigned char client_write_key[32];
unsigned char server_write_key[32];
unsigned char client_iv[16];
unsigned char server_iv[16];

// The hash for the "finished" message to verify the
// integrity of the initial handshake
SHA256_CTX verify_data;

// TLS version (TLS 1.2)
#define TLS_VERSION_MAJOR 3
#define TLS_VERSION_MINOR 3

// TLS record content types
#define TLSR_CHANGE_CIPHER_SPEC 20
#define TLSR_ALERT 21
#define TLSR_HANDSHAKE 22
#define TLSR_DATA 23

// Remote server name for SNI (server-name-indication)
char *servername;

// For proxy mode
char *proxyport;

// Covert data to send for IV covert channel method
unsigned char *ivenc;
int ivenclen, ivencoff;

// Covert data to send for RL covert channel method
unsigned char *rlenc;
int rlenclen, rlencoff, rlencbitpos;

// Covert data to send for CT covert channel method
unsigned char *ctenc;
int ctenclen, ctencoff, ctencbitpos = -1;

// Master seed to generate ivseed and rlseed 
// This seed is used by sender and receiver
unsigned int masterseed;
// Pre-Shared Key between sender and receiver
unsigned int key;
// Random number generator seeds for both encoding methods
unsigned int ivseed, rlseed, ctseed;

// Keep track of empty records and alerts sent
static int emptyrecords = 0, alerts = 0;

// The verbosity, can be increased by one or more -v flags
int verbosity;

// Be quiet flag
int quiet;

// STARTTLS flag
int starttls;

// Number of bytes transmitted
int totalbytes;

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
   fflush(stderr);
   va_end(ap);
}

/* function sockwrite (fd, data, len)
 * Write len bytes of data to the socket specified by fd.
 * If an error occurs, print it and exit.
 * fd   - filedescriptor to write to
 * data - databuffer to send
 * len  - length of data to send
 * returns: number of bytes sent, 0 is EOF
 */
static ssize_t sockwrite (int fd, const void *data, size_t len) {
   ssize_t st = write(fd, data, len);
   if (st < 0) {
      verb(0, "Error writing to socket: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
   }

   return st;
}

/* function covertbytespending()
 * return the number of covert bytes pending in all covert channel types.
 * returns: number of covert bytes pending
 */
static size_t covertbytespending (void) {
   return ctenclen - ctencoff + rlenclen - rlencoff + ivenclen - ivencoff;
}

/* function sockaccept (service)
 * Open a listen socket for the given service and
 * accept a client. Closes the server socket after accepting.
 * service - the service to open (name or port number)
 * returns: filedescriptor of accepted client socket
 */
static int sockaccept (char *service) {
   struct addrinfo hints;
   struct addrinfo *result, *rp;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;
   hints.ai_protocol = 0;

   int st = getaddrinfo(NULL, service, &hints, &result);

   if (st != 0) {
      verb(0, "getaddrinfo: %s\n", gai_strerror(st));
      exit(EXIT_FAILURE);
   }

   int fd = -1, one = 1;
   for (rp = result; rp; rp = rp->ai_next) {
      char addr[128] = "";
      getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, sizeof(addr),
                  NULL, 0, NI_NUMERICHOST);
      verb(0, "Binding %s... ", addr);
      fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd < 0) {
         verb(0, "%s\n", strerror(errno));
         continue;
      }
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      st = bind(fd, rp->ai_addr, rp->ai_addrlen);
      if (st != 0) {
         verb(0, "%s\n", strerror(errno));
         close(fd);
         continue;
      }
      verb(0, "Success!\n");
      break;
   }

   if (fd < 0) {
      verb(0, "Error binding proxy-socket!\n");
      exit(EXIT_FAILURE);
   }

   listen(fd, 128);
   int cl = accept(fd, NULL, NULL);
   if (cl < 0) {
      verb(0, "Error accepting client: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
   }
   close(fd);

   return cl;
}

/* function sockconnect(host, service)
 * Establish an IPv4 TCP connection to the given host/service combination
 * host    - Host to connect to
 * service - Service or port to connect to
 * returns the file descriptor of the connected socket
 */
static int sockconnect (char *host, char *service) {
   struct addrinfo hints;
   struct addrinfo *result, *rp;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0;

   int st = getaddrinfo(host, service, &hints, &result);

   if (st != 0) {
      verb(0, "getaddrinfo: %s\n", gai_strerror(st));
      exit(EXIT_FAILURE);
   }

   int fd = -1;
   for (rp = result; rp; rp = rp->ai_next) {
      char addr[128] = "";
      getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, sizeof(addr),
                  NULL, 0, NI_NUMERICHOST);
      verb(0, "Trying %s... ", addr);
      if (rp->ai_family == AF_INET6) {
         verb(0, "IPv6 not supported by extractor\n");
         continue;
      }
      fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd < 0) {
         verb(0, "%s\n", strerror(errno));
         continue;
      }
      st = connect(fd, rp->ai_addr, rp->ai_addrlen);
      if (st != 0) {
         verb(0, "%s\n", strerror(errno));
         close(fd);
         continue;
      }
      verb(0, "Success!\n");
      break;
   }
   if (fd < 0) {
      verb(0, "Could not establish connection.\n");
      exit(EXIT_FAILURE);
   }

   return fd;
}

/* function getrandom(buf, size)
 * Fill a buffer of the given size with random bytes.
 * buf  - the buffer to fill
 * size - the length of the buffer
 * returns nothing
 */
static void getrandom (unsigned char *buf, int size) {
   while (size--)
      *buf++ = rand();
}

/* function getIV(buf, size)
 * Get an AES initialization vector of a given size, equipped with
 * data for the covert channel.
 * buf  - the buffer of the initialization vector to fill
 * size - the length of the initialization vector (max. 256)
 * returns nothing
 */
static void getIV(unsigned char *buf, int size) {
   assert(size < 256);
   int i = 0, l = size - 1;

   if (ivenclen - ivencoff < size)
      l = ivenclen - ivencoff;

   buf[0] = l; // The length byte
   memcpy(buf+1, ivenc+ivencoff, l); // Copy the covert channel data
   memset(buf+1+l, '\0', size-1-l); // Zero excess space
   // Update the iv encoded data buffer and length
   ivencoff += l;

   for (i = 0; i < size; i++) {
      // XOR the data with the current seed, to avoid
      // detection of suspicious patterns on traffic analysis.
      // The same seed must be used when extracting the data.
      // In this implementation, the initial seed is hidden in
      // the "hello" message, but it is more secure to transmit
      // it out-of-band to avoid detection even if the method
      // is known.
      unsigned char x = rand_r(&ivseed);
      buf[i] ^= x;
   }
}

/* function send_record(fd, contenttype, data, len)
 * Send a single TLS record with the given data to the peer. If encryption
 * is already negotiated, the data already has to be encrypted properly and
 * the MAC has already been added.
 * (see RFC5246 6.2.1 for the record header definition)
 * fd   - the target filedescriptor to which the record is written
 * contenttype - the TLS record content type
 * buf  - the data buffer
 * len  - the length of the data buffer
 * returns nothing
 */
static void send_record (int fd, int contenttype, void *data, int len) {
   char buf[5+len]; // Data length plus 5 bytes record header

   verb(3, "> send_record(): type %d, len %d\n", contenttype, len);
   // Build the record header (see RFC5246 6.2.1)
   buf[0] = contenttype; // e.g. 22 for handshake, 23 for data, etc.
   buf[1] = TLS_VERSION_MAJOR; // TLS major version
   buf[2] = TLS_VERSION_MINOR; // TLS minor version
   buf[3] = len/256; // MSB length
   buf[4] = len;     // LSB length
   memcpy(buf+5, data, len); // Copy the data right after the header

   // If we are currently performing the handshake, calculate the
   // SHA256-sum over all handshake packets sent, for the "finish"
   // message, which contains the hash value for the integrity check
   if (contenttype == TLSR_HANDSHAKE)
      SHA256_Update(&verify_data, data, len);

   // Put the buffer on the wire
   totalbytes += sockwrite(fd, buf, sizeof(buf));
}

/* function send_record_encrypted (fd, contenttype, iv, data, len, rlpad)
 * Encrypt the data (if necessary) and send a TLS record of the specified
 * content type. Also calculates the MAC for the data integrity check.
 * fd          - the target filedescriptor to which the record is written
 * contenttype - the TLS record content type
 * iv          - the initialization vector to use (generated when NULL)
 * data        - the data buffer
 * len         - the length of the data buffer
 * rlpad       - the length of the padding for record length encoding
 * returns: number of data bytes sent
 */
static int send_record_encrypted (int fd, int contenttype, void *iv,
                                  void *data, int len, int rlpad) {
   // TLS uses sequence numbers to avoid replayed records.
   // These numbers are not transmitted explicitly, but counted
   // internally on both sides and usedduring the MAC calculation.
   static unsigned long long seq = 0;

   // Create a buffer for a TLS record header and an
   // AES initialization vector (one AES block, 16 bytes)
   // used for IV encoding of covert data
   unsigned char buf[5+AES_BLOCK_SIZE];

   // Keep track of empty records and alerts sent. OpenSSL has a limit of
   // 31 consecutive empty records and 4 alert messages before closing the
   // connection
   if (len > 0) {
      alerts = (contenttype == TLSR_ALERT) ? alerts + 1 : 0;
      emptyrecords = 0;
   } else {
      emptyrecords++;
   }

   // Build a temporary header for MAC calculation
   buf[0] = contenttype;
   buf[1] = TLS_VERSION_MAJOR; // TLS major version
   buf[2] = TLS_VERSION_MINOR; // TLS minor version
   buf[3] = len/256;
   buf[4] = len;
   if (iv) // Is a custom iv with covert data provided?
      memcpy(buf+5, iv, AES_BLOCK_SIZE); // Copy the initialization vector
   else    // otherwise
      getrandom(buf+5, AES_BLOCK_SIZE); // Just use a random iv
   // Generate the MAC, which is SHA256(seq + recordheader + plaintext)
   unsigned char macdata[sizeof(seq)+5+len];
   // Copy the sequence number with MSB first into the buffer
   assert(sizeof(seq) == 8);
   for (unsigned int i = 0; i < sizeof(seq); i++)
      macdata[i] = ((unsigned char *)&seq)[sizeof(seq)-i-1];
   // Copy the record header into the mac buffer
   memcpy(macdata+sizeof(seq), buf, 5);
   // Copy the plaintext data into the mac buffer
   memcpy(macdata+sizeof(seq)+5, data, len);
   // Finally calculate the MAC
   unsigned int maclen = SHA256_DIGEST_LENGTH;
   unsigned char mac[maclen];
   HMAC(EVP_sha256(), client_write_MAC_key, sizeof(client_write_MAC_key),
        macdata, sizeof(macdata), mac, &maclen);

   // Calculate the padding, which must be _at least_ one byte, _at most_ 255
   // bytes and make the data a multiple of the AES block size (16 bytes).
   int padlen = AES_BLOCK_SIZE - ((len+maclen+1)&0x0f);
   // Add extra padding if needed for record length encoding
#ifndef RLDISABLED
   if (rlpad >= 0) {
      padlen += rlpad;
   } else if (len+maclen+padlen+1 < 96) {
      // If no record length encoding data is pending,
      // make sure that we at least have a record length
      // of 96, so the covert channel receiver knows that.
      padlen += 32;
   }
#endif
   // Build the plaintext block, which consists of:
   // data + mac (sha256-digest) + padding + padding length field
   unsigned char plaintext[len+maclen+padlen+1];
   assert((sizeof(plaintext)%AES_BLOCK_SIZE) == 0);
   // Copy the data into the plaintext buffer
   memcpy(plaintext, data, len);
   // Append the MAC to the plaintext buffer
   memcpy(plaintext+len, mac, maclen);
   // Add the padding
   for (int i = 0; i < padlen; i++)
      plaintext[len+maclen+i] = padlen;
   // Add the padding length field
   plaintext[len+maclen+padlen] = padlen;

   // Perform the encryption
   unsigned char ciphertext[sizeof(plaintext)]; // ciphertext buffer
   int _len, ciphertextlen;
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   // Initialize encryption with AES256 in cbc mode and the client write key.
   // The IV is stored at buf+5
   EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, client_write_key, buf+5);
   // Disable padding, we performed it manually
   EVP_CIPHER_CTX_set_padding(ctx, 0);
   // Do the encryption of the plaintext
   EVP_EncryptUpdate(ctx, ciphertext, &_len, plaintext, sizeof(plaintext));
   ciphertextlen = _len;
   EVP_EncryptFinal_ex(ctx, ciphertext+_len, &_len);
   ciphertextlen += _len;
   EVP_CIPHER_CTX_free(ctx);
   assert(ciphertextlen == (int) sizeof(ciphertext));

   // The length of the encrypted data is the ciphertext length plus
   // the IV block
   int l = ciphertextlen+AES_BLOCK_SIZE;
   // Update the length in the TLS record header
   buf[3] = l/256;
   buf[4] = l%256;
   // The buffer to send is the TLS record header and IV stored in buf
   // plus the ciphertext
   char sendbuf[sizeof(buf)+ciphertextlen];
   // Copy TLS record header and IV block
   memcpy(sendbuf, buf, sizeof(buf));
   // Copy the ciphertext of the data
   memcpy(sendbuf+sizeof(buf), ciphertext, ciphertextlen);
   // send the encrypted TLS record on the wire
   verb(3, "> send_record_encrypted(): type %d, len %d (%d)\n", buf[0], l, len);
   totalbytes += sockwrite(fd, sendbuf, sizeof(sendbuf));
   // Increment the sequence number for the next block to send
   seq++;

   return len;
}

/* function send_record_encrypted_cc (fd, contenttype, data, len)
 * Send an encrypted record, but hide covert data if it is pending in
 * one of the channels.
 * fd          - filedescriptor of the TLS socket
 * contenttype - content type of the record
 * data        - record data to send
 * len         - length of the record data
 * returns: number of data bytes sent
 */
static int send_record_encrypted_cc (int fd, int contenttype,
                                     void *data, int len) {
   // The initialization vector, which sometimes contains covert data
   unsigned char _iv[AES_BLOCK_SIZE], *iv = _iv;

   // The extra padding used for the AES encryption (max. 240 bytes)
   // Note, that this is additional padding to the necessary padding,
   // used for length encoding of covert data. -1 means, no record
   // length encoded data is pending.
   int rlpad = -1;

   if (contenttype == TLSR_DATA) {
      // If we send a data chunk, add covert data pending for
      // IV encoding.
      getIV(iv, AES_BLOCK_SIZE);

      // If length encoding data is pending, see how much extra padding
      // has to be added
      if (rlenclen-rlencoff > 0) {
         if (rlencbitpos == 0) {
            // First bit, scramble the byte
            rlenc[rlencoff] ^= ((unsigned char) rand_r(&rlseed));
         }
         rlpad = !!(rlenc[rlencoff]&(1<<rlencbitpos++))*16;
         if (rlencbitpos == 8) {
            rlencoff++;
            rlencbitpos = 0;
         }
      }

      // If contenttype encoding data is pending, see if we have to send
      // TLS alert messages.
      while (ctenclen-ctencoff > 0) {
         if (ctencbitpos == -1) {
            // First bit, scramble the byte and 
            // send a start alert message to signal
            // the start of a contenttype encoded byte
            ctenc[ctencoff] ^= ((unsigned char) rand_r(&ctseed));
            // We send a "user cancelled" warning, which is usually ignored
            // by the peer
            ctencbitpos++;
            send_record_encrypted(fd, TLSR_ALERT, NULL, "\x01\x5a", 2, -1);
            if (alerts == 4)
               break; // Send a data byte after 4 alerts
         }
         int bit = ctenc[ctencoff] & (1 << ctencbitpos++);
         if (ctencbitpos == 8) {
            ctencoff++;
            ctencbitpos = -1;
         }
         if (bit) // We have a 1-bit, break and send a DATA record
            break;
         // We send a "user cancelled" warning, which is usually ignored
         // by the peer
         send_record_encrypted(fd, TLSR_ALERT, NULL, "\x01\x5a", 2, -1);
         if (alerts == 4)
            break; // Send a data byte after 4 alerts
      }
      if (covertbytespending() > 0 || rlpad >= 0) {
         if (ctenclen - ctencoff > 0 || emptyrecords > 31)
            // Send just a single byte
            len = 1;
         else
            len = 0;
      }
   } else {
      iv = NULL;
   }

   return send_record_encrypted(fd, contenttype, iv, data, len, rlpad);
}


/* function send_encrypted_data (fd, string, len)
 * Takes a data block and sends it in several TLS record
 * chunks, until all covert data is transmitted.
 * fd   - the socket filedescriptor with the negotiated TLS connection
 * data - The data to send (e.g. a HTTP request)
 * len  - the length of the data
 * returns nothing
 */
static void send_encrypted_data (int fd, char *string, int l) {
   // Send out the chunks until all regular data is transmitted
   do {
      int st = send_record_encrypted_cc(fd, 23, string, l);
      l -= st;
      string += st;
   } while (l > 0);
}

/* function read_record(fd, plain)
 * read a single TLS record from our peer. The flag "plain" denotes,
 * if we are currently in the initial handshake, which is unencrypted.
 * (see RFC5246 6.2.1 for the record header definition)
 * fd    - the filedescriptor of the TLS socket
 * plain - flag: TRUE, if we are in the initial (unencrypted) handshake
 * returns: the record
 */
static unsigned char *read_record(int fd, int plain) {
   // Allocate a buffer for the record, which can be at maximum
   // 16389 bytes long (5 bytes record header + 2^14 bytes data)
   // (see RFC5246 6.2.1 for the record header definition)
   unsigned char *buf = malloc(18437);
   // Read the record header
   int rhl = 0;
   do {
      int st = read(fd, buf+rhl, 5-rhl);
      if (st <= 0) {
         verb(3, "read_record: Read error: %d (%s)\n", st, strerror(errno));
         free(buf);
         return NULL;
      }
      rhl += st;
   } while (rhl < 5);
   // Calculate the data length from the record header fields
   int len = buf[3]*256+buf[4];
   if (len > 18432) {
      // The data length is at most 16384+2048 bytes, larger
      // values are erroneous
      free(buf);
      return NULL;
   }

   // Read "len" bytes into the buffer right behind the record
   // header
   int l = len;
   unsigned char *ptr = buf + 5;
   do {
      int st = read(fd, ptr, l);
      if (st <= 0) {
         // Short read (EOF) or read error
         free(buf);
         return NULL;
      }
      ptr += st;
      l -= st;
   } while (l);

   verb(3, "< read_record(): type %d, len %d\n", buf[0], len);

   // Record content type is "handshake": Update the hash value for the
   // "finished" message (see RFC5246 7.4.9)
   if (buf[0] == TLSR_HANDSHAKE && plain) {
      SHA256_Update(&verify_data, buf+5, len);
   }

   // We received an "alert" message: print out the message here if it is
   // unencrypted.
   if (buf[0] == TLSR_ALERT && plain) {
      verb(0, "Alert: %s %d\n", (buf[5]==1)?"Warning":"Fatal", buf[6]);
   }

   // Return the record
   return buf;
}

/* function read_encrypted(fd, len)
 * Read and decrypt an encrypted record from our peer.
 * fd   - the TLS socket file descriptor
 * *len - pointer to tell the length of the decrypted record to the caller
 * returns: pointer to the decrypted record
 */
static unsigned char *read_encrypted(int fd, int *len) {
   // Read the encrypted record
   unsigned char *buf = read_record(fd, 0);

   if (buf == NULL)
      return NULL; // An error has occurred

   // Decrypt the record
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   // Use the "server write key" to decrypt the message and the initialization
   // vector, which is right behind the record header (buf+5)
   EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, server_write_key, buf+5);
   EVP_CIPHER_CTX_set_padding(ctx, 0); // We handle padding manually
   // "outl" bytes have to be decrypted. This is the length specified in
   // the record header minus the initialization vector, which is
   // of length AES_BLOCK_SIZE
   int outl = buf[3]*256+buf[4]-AES_BLOCK_SIZE;
   // Buffer for the decrypted record
   unsigned char *out = malloc(outl+5);
   // Copy the record header into the decrypted record buffer
   memcpy(out, buf, 5);
   // Decrypt the data. The encrypted data starts behind the record header
   // and the IV at (buf+5+AES_BLOCK_SIZE). The decrypted data is stored
   // in the decrypted record output buffer right behind the record header
   // at (out+5).
   EVP_DecryptUpdate(ctx, out+5, &outl, buf+5+AES_BLOCK_SIZE, outl);
   free(buf); // The encrypted buffer is no longer needed now.
   // If the len pointer is valid, store the data length there.
   // The length is: the encrypted data length (outl) minus the
   // digest length (mac), minus the padding and minus one byte for the
   // padding length field. The padding length field is
   // stored in the last byte of the buffer (out[outl+5-1]). 
   // (see also RFC5246 6.2.3.2)
   if (len) *len = outl - SHA256_DIGEST_LENGTH - out[outl+5-1]-1;

   // Return the decrypted record
   return out;
}

/* function process_handshake_record ()
 * Process a TLS handshake record. Reassemble the handshake messages
 * and return a full message, when it is available.
 * rec - Buffer with a single, complete TLS record. May be NULL
 * returns: A complete TLS message or NULL, if none is available yet
 */
static unsigned char *process_handshake_record(unsigned char *rec) {
   static unsigned char *msg;
   static int msglen;

   if (rec) {
      // We have new data, add it to the message buffer
      int l = rec[3]*256+rec[4];
      msg = realloc(msg, msglen+l);
      memcpy(msg+msglen, rec + 5, l);
      msglen += l;
   }

   unsigned char *ret = NULL;
   if (msglen >= 4) { // Minimum  message length is 4
      int l = msg[1]*256*256 + msg[2]*256 + msg[3];
      if (msglen >= l + 4) {
         // We have a full message, extract and
         // return it. Leave the remaining bytes
         // in the buffer, if necessary; it is
         // part of the next message.
         ret = malloc(l+4);
         memcpy(ret, msg, l+4);
         memmove(msg, msg+l+4, msglen-l-4);
         msglen -= (l+4);
      }
   }

   // Return the message. More messages may be pending
   // already.
   return ret;
}

/* function send_client_hello (fd)
 * Construct and send the "hello" initial handshake message.
 * For the structure, see RFC5246 7.4.1.2
 * fd - the filedescriptor of the TLS socket
 * returns nothing
 */
static void send_client_hello (int fd) {
   unsigned char hello[1024], hellolen = 45;

   // Handshake type: Client Hello
   hello[0] = 1;

   // Packet Length, initialized with 0 (adjusted later)
   hello[1] = 0;
   hello[2] = 0;
   hello[3] = 0;

   hello[4] = TLS_VERSION_MAJOR; // TLS major version
   hello[5] = TLS_VERSION_MINOR; // TLS minor version

   // 32 bytes "Random" data; the first 4 bytes are
   // gmt_unix_time by convention.
   time_t now = htonl(time(NULL));
   memcpy(hello+6, &now, 4);

   // The following 28 bytes should be random, but we
   // use it for metadata of our covert channels. In
   // the next 4 bytes, the master seed for generating
   // the seeds for the two covert channel types 
   // "iv encoding" and "len encoding" is stored.
   memcpy(hello+10, &masterseed, 4);
   // Then, 24 bytes are generated using the "iv seed".
   // The covert channel receiver validates these 24
   // bytes to check, if a covert channel exists.
   for (int i = 14; i < 38; i++)
      hello[i] = rand_r(&ivseed);
   // Store the clientserverrandom, since it is needed to
   // generate the key material
   memcpy(clientserverrandom, hello+6, 32);

   // Session-ID length. Zero here, we do not need it
   hello[38] = 0;

   // Cipher Suites length: 2 bytes per cipher suite, and
   // we only support one.
   hello[39] = 0;
   hello[40] = 2;

   // List of cipher suites: Only one element
   hello[41] = 0;
   hello[42] = 0x3D; // TLS_RSA_WITH_AES_256_CBC_SHA256

   // Number of compression methods
   hello[43] = 1;
   // List of compression methods. We use only the
   // NULL compression method: no compression
   hello[44] = 0;

   // Some servers today insist to have a server name
   // transmitted with the SNI extension.
   // (see RFC6066 Section 3)
   if (servername) {
      verb(3, "  Using SNI name '%s'\n", servername);
      int snl = strlen(servername);
      // Total Extensions length:
      // snl (server name length)
      //   2 bytes extension type
      // + 2 bytes extension length
      // + 2 bytes name list length
      // + 1 byte name type
      // + 2 bytes hostname length
      // + snl (server name length) bytes
      hello[45] = 0;
      hello[46] = 2+2+2+1+2+snl; 

      // Extension Type 0 is SNI (server name indication)
      hello[47] = 0;
      hello[48] = 0;
      // Extension length
      hello[49] = 0;
      hello[50] = snl+5;
      // Name List Length
      hello[51] = 0;
      hello[52] = snl+3;
      // Name Type: 0 (Hostname)
      hello[53] = 0; // Type: hostname
      // Hostname length
      hello[54] = 0;
      hello[55] = snl;
      // Copy the hostname into the hello packet
      memcpy(hello+56, servername, snl);
      // and adjust the total hello packet length
      hellolen += 11+snl;
   }

   // Set the length of the hello packet in the message header
   // to the total packet length minus 4 bytes, since the
   // "type" (1 byte) and "length" (3 bytes) field isn't
   // accounted.
   hello[1] = (hellolen-1-3)/65536;
   hello[2] = (hellolen-1-3)/256;
   hello[3] = hellolen-1-3;

   // Wrap it into a record of type "handshake" and put it on the wire.
   send_record(fd, TLSR_HANDSHAKE, hello, hellolen);
}

/* function send_clientkex (fd, crt)
 * Send the client key exchange message. The pre-master secret is the
 * fundamental key for generating the key material for this TLS connection.
 * (see RFC5246 7.4.7.)
 * It is transmitted encrypted using the public key, that comes with the
 * server certificate.
 * fd  - the file descriptor of the TLS socket
 * crt - the server certificate received by the "server certificate" message
 */
static void send_clientkex (int fd, X509 *crt) {
   unsigned char pms[1024];

   verb(2, "> Sending 'client key exchange'\n");

   // Message type: 16 (Client Key Exchange)
   pms[0] = 16;

   // Message length
   pms[1] = 0;
   pms[2] = 0;
   pms[3] = 50;

   // Generate the 48-byte pre-master secret consisting of
   // tls major/minor version and 46 bytes random data
   pms[4] = TLS_VERSION_MAJOR;  // TLS major version
   pms[5] = TLS_VERSION_MINOR;  // TLS minor version
   getrandom(pms+6, 46); // Random data
   // Save the pre-master secret for future use
   memcpy(premastersecret, pms+4, sizeof(premastersecret));

   // Retrieve the public key from the server certificate
   EVP_PKEY *pubkey = X509_get_pubkey (crt);
   EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
   if (!ctx) {
      verb(0, "Error setting up EVP_PKEY_CTX\n");
      exit(EXIT_FAILURE);
   }
   // Encrypt the pre-master secret using the public key
   // into a temporary buffer
   EVP_PKEY_encrypt_init(ctx);
   unsigned char out[1000];
   size_t outlen = 1000;
   int st = EVP_PKEY_encrypt(ctx, out, &outlen, pms+4, 48);
   if (st < 0) {
      // An error occurred, bail out
      verb(0, "Error encrypting pms\n");
      exit(EXIT_FAILURE);
   }
   // Overwrite the plaintext pre-master secret with the
   // encrypted version
   memcpy(pms+6, out, outlen);

   // Re-Set the length field of the message with the actual
   // length of the message
   pms[1] = 0;
   pms[2] = (outlen+2)/256;
   pms[3] = (outlen+2)%256;
   // Length of the public-key-encrypted pre master secret
   pms[4] = outlen/256;
   pms[5] = outlen%256;

   // Send the record of type "Handshake on the wire
   send_record(fd, TLSR_HANDSHAKE, pms, outlen+6);
}

/* function PRF (secret, secretlen, label, seed, seedlen, out, outlen)
 * This is the pseudo-random-function as defined in RFC5246 Section 5
 * secret    - the premaster secret
 * secretlen - length of the premaster secret
 * label     - type of key material generated
 * seed      - random data as seed
 * seedlen   - length of the seed
 * out       - output buffer
 * outlen    - length of the output buffer to fill
 * returns nothing
 */
static void PRF(unsigned char *secret, int secretlen, char *label,
             unsigned char *seed, int seedlen, unsigned char *out, int outlen) {
   // The label specifies the usage of the data and
   // has influence on the generated PRF data
   int ll = strlen(label);
   unsigned char labelseed[ll+seedlen];

   // The concatenated label and seed (called labelseed) is used as
   // initial input to the HMAC hash function and is always appended
   // to the digest.
   memcpy(labelseed, label, ll);
   memcpy(labelseed+ll, seed, seedlen);

   unsigned char *ptr = out;
   unsigned int resultlen;
   // Reserve space for one digest + size of the labelseed, because
   // the label is always appended to the digest.
   unsigned char A[SHA256_DIGEST_LENGTH+sizeof(labelseed)];
   // The labelseed is A(0)
   // Calculate the HMAC with the given secret and A(0) for the first
   // iteration. The result is placed in A. This is A(1) now. (see RFC5246 5.)
   HMAC(EVP_sha256(), secret, secretlen, labelseed,
        sizeof(labelseed), A, &resultlen);
   memcpy(A+SHA256_DIGEST_LENGTH, labelseed, sizeof(labelseed));

   do {
      // A(i) + labelseed is stored in A. Now calculate the next chunk of PRF data.
      unsigned char *md = HMAC(EVP_sha256(), secret, secretlen,
                               A, sizeof(A), NULL, &resultlen);
      if (outlen < (int) resultlen) {
         // We have generated more bytes than we need.
         // Only copy as much as needed and end the loop.
         memcpy(ptr, md, outlen);
         break;
      } 

      // Copy the digest into our result buffer for the PRF,
      // advance the buffer pointer and adjust the remaining
      // amount of data needed.
      memcpy(ptr, md, resultlen);
      ptr += resultlen;
      outlen -= resultlen;

      // Now calculate A(i+1) from A(i) and iterate the process
      md = HMAC(EVP_sha256(), secret, secretlen, A, SHA256_DIGEST_LENGTH,
                NULL, &resultlen); 
      memcpy(A, md, SHA256_DIGEST_LENGTH);
      memcpy(A+SHA256_DIGEST_LENGTH, labelseed, sizeof(labelseed));
   } while (1);
}

/* function generate_key_material()
 * Generate the key material used in this TLS connection.
 * This contains the
 * - client/server write MAC key (for record MAC authentication)
 * - client/server write key (for encrypting the data)
 * - client/server iv (unused in this implementation)
 * (see RFC5246 6.3)
 * The keys are stored in global buffers.
 * returns nothing
 */
static void generate_key_material (void) {
   // Use the pseudo random function to generate the master key from
   // the premaster secret and the clientserverrandom from the hello
   // messages
   PRF(premastersecret, sizeof(premastersecret), "master secret",
       clientserverrandom, sizeof(clientserverrandom),
       masterkey, sizeof(masterkey));

   // The serverclientrandom is simply the clientserverrandom with
   // the serverrandom first and the clientrandom following.
   unsigned char serverclientrandom[64];
   memcpy(serverclientrandom, clientserverrandom+32, 32);
   memcpy(serverclientrandom+32, clientserverrandom, 32);

   // Generate the key block with the pseudo random function using
   // the master key and the serverclientrandom.
   unsigned char key_block[160];
   PRF(masterkey, sizeof(masterkey), "key expansion",
       serverclientrandom, sizeof(serverclientrandom),
       key_block, sizeof(key_block));

   // Split the key block into the individual keys
   memcpy(client_write_MAC_key, key_block, 32);
   memcpy(server_write_MAC_key, key_block+32, 32);
   memcpy(client_write_key, key_block+64, 32);
   memcpy(server_write_key, key_block+96, 32);
   memcpy(client_iv, key_block+128, 16);
   memcpy(server_iv, key_block+144, 16);
}

/* function send_finished(fd)
 * Send the "Finished" message to our TLS peer. This message contains
 * an integrity check value over all handshake messages.
 * (see RFC5246 7.4.9)
 * fd - the filedescriptor of the TLS socket
 */
static void send_finished (int fd) {

   verb(2, "> Sending 'client finished' message\n");

   // Generate the SHA256 hash over all handshake
   // messages. This hash was always updated in
   // the "send_record" function and the final
   // value is now stored in the buffer "md".
   unsigned char md[SHA256_DIGEST_LENGTH];
   SHA256_Final(md, &verify_data);

   // Now construct the "finished" message
   unsigned char verify[16];
   // Message type is "Finished" (20)
   verify[0] = 20;

   // Length of the message (without message header)
   verify[1] = 0;
   verify[2] = 0;
   verify[3] = sizeof(verify)-4;

   // Now generate 12 bytes of data using the Pseudo-Random-Function
   // with the handshake message digest as seed and
   // store it in the verify message right after the header.
   PRF(masterkey, sizeof(masterkey), "client finished",
       md, sizeof(md), verify+4, 12);

   // Wrap the message into a record of type "Handshake"
   // and put it on the wire
   send_record_encrypted_cc(fd, TLSR_HANDSHAKE, verify, sizeof(verify));
}

/* function addcovertdata (data, datalen, method)
 * Add a data buffer to a covert channel buffer for the specified
 * method.
 * data    - data buffer
 * datalen - length of the data buffer
 * method - covert channel method: 0 - iv encoding
 *                                 1 - record length encoding
 *                                 2 - content type encoding
 * returns nothing
 */ 
static void addcovertdata (void *data, int datalen, int method) {
   if (method == 0) {
      // Add covert data for IV encoding
      ivenc = realloc(ivenc, ivenclen+datalen);
      memcpy(ivenc+ivenclen, data, datalen);
      ivenclen += datalen;
   } else if (method == 1) {
      // Add covert data for RL encoding
      rlenc = realloc(rlenc, rlenclen+datalen);
      memcpy(rlenc+rlenclen, data, datalen);
      rlenclen += datalen;
   } else if (method == 2) {
      // Add covert data for CT encoding
      ctenc = realloc(ctenc, ctenclen+datalen);
      memcpy(ctenc+ctenclen, data, datalen);
      ctenclen += datalen;
   }
}

/* function addfile (file, method)
 * Read a file and add it to the covert data buffer using
 * the requested method.
 * The format is: \xf2 [size (4 bytes, MSB)] [data] [filename] \x00
 * file   - the file name containing the covert data
 * method - covert channel method: 0 - iv encoding
 *                                 1 - record length encoding
 *                                 2 - content type encoding
 * returns nothing
 */
static void addfile (char *file, int method) {
   // Open the file
   FILE *f = fopen(file, "r");
   if (!f) { // Bail out on error
      verb(0, "Error opening %s: %s\n", file, strerror(errno));
      return;
   }

   // Find out filesize
   fseek(f, 0, SEEK_END);
   long size = ftell(f);
   fseek(f, 0, SEEK_SET);

   addcovertdata("\xf2", 1, method); // Identifier for "file"

   // Serialize the file size into a buffer and add it to
   // the covert data buffer. Format is 4 bytes MSB
   unsigned char sizebuf[4];
   sizebuf[0] = size >> 24;
   sizebuf[1] = size >> 16;
   sizebuf[2] = size >> 8;
   sizebuf[3] = size;
   addcovertdata(sizebuf, 4, method);

   int datalen = 0;
   size_t l;
   do {
      char data[1024];
      l = fread(data, 1, sizeof(data), f); // Read a data block
      addcovertdata(data, l, method); // Add to covert channel buffer
      datalen += l; // Update the byte counter
   } while (l); // End-of-file if 0 is returned
   fclose(f); // Close the stream

   // Finally add filename (without path)
   char *ptr = strrchr(file, '/');
   if (ptr)
      ptr = ptr + 1;
   else
      ptr = file;
   addcovertdata(ptr, strlen(ptr)+1, method);
   verb(1, "Added file %s with %d bytes of covert data for channel type %d\n",
        file, datalen, method);
}

/* function addfile (file, method)
 * Read a file and add it to the covert data buffer using
 * the requested method.
 * The format is: \xf1 [ASCII-message] \x00 
 * msg    - the message to send
 * method - covert channel method: 0 - iv encoding
 *                                 1 - record length encoding
 *                                 2 - content type encoding
 * returns: nothing
 */
static void addmessage (char *msg, int method) {
   addcovertdata("\xf1", 1, method); // Identifier for "message"
   addcovertdata(msg, strlen(msg)+1, method); // Add the 0-terminated message
   verb(1, "Added message with %d bytes of covert data for channel type %d\n",
        strlen(msg)+1, method);
}

/* function usage()
 * Display a short description of the program usage and exit.
 * returns: nothing
 */
static void usage (void) {
   verb(0, "Usage: tlscc [-v] [-q] [-t] -h <host> [-p <port>] [-x <port>] "
                           "[-m method] [-f <file>] [-d <msg>] [-s <sni>]\n"
    "           -v            Increase verbosity (use before other options!)\n"
    "           -h <host>     Host to connect to (IP)\n"
    "           -s <sni>      Server name to connect to (default: hostname)\n"
    "           -p <port>     Port to connect to (default: 443)\n"
    "           -x <port>     Proxy mode, listen for client on specified port\n"
    "           -m <iv|rl|ct> Set method: iv (initialization vector, default)\n"
    "                                     rl (record length encoding)\n"
    "                                     ct (content type encoding)\n"
    "                         Is used for subsequent(!) -f or -d options\n"
    "           -f <file>     Covert datafile to transmit (multiple)\n"
    "           -d <msg>      Covert message to transmit (multiple)\n"
    "           -q            quiet, do not output server response\n"
    "           -t            Perform STARTTLS for IMAP and SMTP\n"
    "           -k <key>      A 32-bit integer pre-shared key (default: 0)\n"
    "\n");
   exit(EXIT_FAILURE);
}

/* function starttls(fd)
 * Issue the STARTTLS commando for IMAP and SMTP
 * fd - TLS socket file descriptor
 * returns: nothing
 */
static char greeting[1024]; // Save greeting for the client
static void do_starttls (int fd) {
   verb(1, "Waiting for STARTTLS trigger...\n");

   // Read the protocol greeting for SMTP or IMAP
   int st = read(fd, greeting, sizeof(greeting));
   if (st <= 0) {
      verb(0, "Error: Connection closed (STARTTLS)\n");
      exit(EXIT_FAILURE);
   }
   greeting[st] = 0;
   verb(1, "STARTTLS1: %s\n", greeting);

   // Determine the protocol
   if (strstr(greeting, "220 ") == greeting) {
      // SMTP detected
      write(fd, "STARTTLS\n", 9);
   } else if (strstr(greeting, "* OK ") == greeting) {
      // IMAP detected
      write(fd, "X STARTTLS\n", 11);
      // Overwrite the greeting to delete a possible
      // embedded capability string. We want the client
      // to ask for the capabilities after doing TLS,
      // because prior to TLS no authentication options
      // are available
      strcpy(greeting, "* OK IMAP server\n");
   } else {
      // Unknown protocol
      verb(0, "Error: STARTTLS: unsupported protocol\n");
      exit(EXIT_FAILURE);
   }


   // Check the response from the server
   char buf[1024];
   st = read(fd, buf, sizeof(buf));
   buf[st] = 0;
   verb(1, "STARTTLS2: %s\n", buf);
   if (strstr(buf, "220 ") == buf) {
      // SMTP STARTTLS succeeded
      verb(1, "SMTP: STARTTLS succeeded\n");
   } else if (strstr(buf, "X OK ") == buf) {
      // IMAP STARTTLS succeeded
      verb(1, "IMAP: STARTTLS succeeded\n");
   } else {
      // Protocol failure
      verb(0, "Error: STARTTLS failed\n");
      exit(EXIT_FAILURE);
   }
}

/* function tls_init (fd)
 * Performs the initial TLS handshake with the TLS server connected to
 * filedescriptor fd. Returns after the "server finished" message, when
 * the socket is prepared to exchange the tls encrypted data.
 * fd  - filedescriptor of the tls socket
 * returns: nothing
 */
static void tls_init (int fd) {
   int certificate_request = 0; // client certificate requested flag
   if (starttls) // Issue starttls for IMAP and SMTP
      do_starttls(fd);
   // Initialize the handshake integrity check digest
   SHA256_Init(&verify_data);

   // ==== Start of the Initial Handshake ====
   // An overview of the initial handshake can be found in
   // RFC5246 Section 7.3.

   // Send our client hello message
   verb(2, "> Sending 'client hello'\n");
   send_client_hello(fd);

   X509 *crt = NULL;
   // Parse incoming server hello messages from our TLS peer
   do {
      unsigned char *msg = process_handshake_record(NULL);
      while (!msg) {
         // Read a (plaintext) record
         unsigned char *buf = read_record(fd, 1);

         if (buf == NULL) {
            // Close during initial handshake: this
            // is an error.
            verb(0, "ERROR: Connection closed unexpectedly\n");
            exit(EXIT_FAILURE);
         }
         if (buf[0] != TLSR_HANDSHAKE) {
            verb(0, "ERROR: Unexpected record %d\n", buf[0]);
            exit(EXIT_FAILURE);
         }
         msg = process_handshake_record(buf);
         free(buf);
      }
      if (msg[0] == 2) {
         // We received the server hello. Save the
         // random data block provided by the server.
         verb(2, "< Received 'server hello'\n");
         memcpy(clientserverrandom+32, msg+6, 32);
      } else if (msg[0] == 11) {
         // We received a certificate from the server.
         verb(2, "< Received 'server certificate'\n");
         // Calculate the length
         int certlen = msg[7]*65536+msg[8]*256+msg[9];
         // And try to parse the certificate into an
         // X509 structure.
         const unsigned char *ptr = msg+10;
         crt = d2i_X509(NULL, &ptr, certlen);
         if (!crt) {
            // Parsing failed, bail out
            verb(0, "ERROR: Unable to parse server certificate\n");
            exit(EXIT_FAILURE);
         }
      } else if (msg[0] == 13) {
         // Server requests a certificate from the client,
         // send an empty certificate list later
         verb(2, "< Received 'certificate request'\n");
         certificate_request = 1;
      } else if (msg[0] == 14) {
         // Server hello done received, exit the loop
         verb(2, "< Received 'server hello done'\n");
         break;
      } else {
         verb(2, "< Received handshake message type %d\n", msg[0]);
      }
   } while (1);

   if (certificate_request) {
      // Server requested a certificate from us, so we
      // send an empty client certificate list.
      // Format: 0b       - Type 11: Certificate Message
      //         00 00 03 - Message          length: 3 bytes
      //         00 00 00 - Certificate list length: 0 bytes
      verb(2, "> Sending 'client certificate list (empty)'\n");
      send_record(fd, TLSR_HANDSHAKE, "\x0b\x00\x00\x03\x00\x00\x00", 7);
   }

   // Send client key exchange
   send_clientkex(fd, crt);

   // Generate the key material
   generate_key_material();

   // Send Change Cipher Spec. After sending this message all following
   // outgoing messages have to be encrypted
   verb(2, "> Sending 'change cipher spec'\n");
   send_record(fd, TLSR_CHANGE_CIPHER_SPEC, (unsigned char *)"\x01", 1);

   verb(2, "> Sending 'client finished'\n");
   // Send Client finished message
   send_finished(fd);

   // Wait for server Change Cipher Spec
   while (1) {
      unsigned char *buf = read_record(fd, 1);
      if (buf == NULL) {
         return; // an error happened
      }
      if (buf[0] == TLSR_CHANGE_CIPHER_SPEC) {
         verb(2, "< Received 'change cipher spec'\n");
         // From now on, all received messages
         // are encrypted
         break;
      }
   }

   // Wait for "Server finished" message
   while (1) {
      unsigned char *buf = read_encrypted(fd, NULL);
      unsigned char *msg = process_handshake_record(buf);
      free(buf);

      if (msg && msg[0] == 20) {
         verb(2, "< Received 'server finished'\n");
         // We got the "Server finished" message.
         // We could check the digest here, but
         // it's not so important for the purpose
         // of our covert channel.
         break;
      }
   } 

   // ==== End of initial handshake ====
   // The initial handshake is now completed on both sides,
   // we are ready to transmit (encrypted) data now (and
   // along with it, our covert data).
}

/* function tls_read (fd, l)
 * reads tls encrypted data from the socket and returns it in plaintext.
 * Also handles alerts and shutdown messages.
 * fd - filedescriptor of the TLS socket
 * l  - out parameter filled with the number of plaintext bytes read
 * returns: the data buffer (must be freed by the caller)
 */
unsigned char *tls_read (int fd, int *l) {
   do {
      int len;
      unsigned char *buf = read_encrypted(fd, &len);
      if (!buf) {
         // The server closed the connection without
         // sending an "alert", this is an error.
         verb(0, "ERROR: Unclean shutdown\n");
         break;
      }
      if (buf[0] == TLSR_DATA) {
         // Incoming data
         verb(2, "< Received %d bytes of data\n", len);
         *l = len;
         memmove(buf, buf+5, len);
         return buf;
      }
      if (buf[0] == TLSR_ALERT) {
         if (buf[5] != 1 || buf[6] != 0) {
            // This is a real warning or error, print it.
            verb(0, "\nAlert: %s %d\n", (buf[5]==1)?"Warning":"Fatal", buf[6]);
         }
         else {
            // This is a clean TLS connection shutdown.
            verb(1, "\nTLS Connection shutdown\n");
            // Send a shutdown message ourselves
            send_record_encrypted_cc(fd, TLSR_ALERT, "\x01\x00", 2);
            // The TLS channel was cleanly closed now, exit.
            break;
         }
      }
   } while (1);

   return NULL;
}

/* function tls_write (fd, buf, len)
 * Encrypt and send data to the TLS socket.
 * fd  - the TLS socket to write to
 * buf - the plaintext data to encrypt and send
 * len - the length of the data
 */
void tls_write (int fd, char *buf, int len) {
   send_encrypted_data(fd, buf, len);
}

/* function do_https_request (host, service)
 * Perform a https request on the given host/service pair.
 * host    - The hostname to connect to
 * service - The service to connect to
 * returns nothing
 */
static void do_https_request (char *host, char *service) {
   // Open a plain TCP socket connection
   int fd = sockconnect(host, service);

   // Do the tls handshakes
   tls_init(fd);

   // Now send a http(s) request through the TLS channel
   char str[1024];
   snprintf(str, sizeof(str),
   "GET /readme.txt HTTP/1.1\r\n"
   "Host: %s\r\n"
   "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:61.0) "
                                              " Gecko/20100101 Firefox/61.0\r\n"
   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
   "Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n"
   "Accept-Encoding: plain\r\n"
   "Connection: close\r\n"
   "", servername ? servername : "localhost");
   // This transmits the string encrypted and also the data in covert
   // channels (iv encoded, rl encoded or even both)
   verb(2, "> Sending HTTP request\n");
   verb(4, str);
   send_encrypted_data(fd, str, strlen(str));
   // If there is still covert data pending, keep sending more headers.
   while (covertbytespending() > 0) {
      verb(2, "Still %d bytes pending, sending header\n", covertbytespending());
      send_encrypted_data(fd, "X-HTTP-DUMMY-HEADER: Hello World!\r\n", 35);
   }

   // Now finish the request with a single empty line
   send_encrypted_data(fd, "\r\n", 2);

   // Receive the response to the HTTP request from the server and shut
   // the TLS channel down cleanly.
   unsigned char *buf;
   do {
      int len;
      buf = tls_read(fd, &len);
      if (buf && !quiet) {
         for (int i = 0; i < len; i++) {
            if (!isprint(buf[i+5]) && !isspace(buf[i+5]))
               putchar('.');
            else
               putchar(buf[i+5]);
         }
         putchar('\n');
         free(buf);
      }
   } while (buf);
}

static void do_proxy_request (char *port, char *host, char *service) {
   verb(1, "Waiting for client on port %s...\n", port);
   // Open a listen port and wait for client connection
   int cl = sockaccept(port);
   verb(1, "Proxy client accepted, connecting to server...\n");
   int srv = sockconnect(host, service);
   verb(1, "Network connection established\n");
   tls_init(srv);
   verb(1, "TLS handshake completed\n");
   verb(0, "\nInjection commands: <CHANNEL>:<DATA>\n");
   verb(0, "   CHANNEL: IV|RL|CT\n");
   verb(0, "      DATA: Any ASCII message\n");
   verb(0, "Enter Command:\n");

   if (starttls) {
      // STARTTLS was performed, send the greeting to the client
      write(cl, greeting, strlen(greeting));
   }
   while (1) {
      char line[1024], *buf = line;
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(srv, &fds);
      FD_SET(cl, &fds);
      FD_SET(fileno(stdin), &fds);
      int st = select((srv>cl)?srv+1:cl+1, &fds, NULL, NULL, NULL);
      if (st < 0) {
         verb(0, "Error select(): %s\n", strerror(errno));
         break;
      }
      if (FD_ISSET(cl, &fds)) {
         char buf[1024];
         int l = read(cl, buf, sizeof(buf));
         if (l <= 0) {
            // EOF from proxy, send a shutdown message
            verb(3, "Client closed connection\n");
            send_record_encrypted_cc(srv, TLSR_ALERT, "\x01\x00", 2);
            break;
         }
         buf[l] = 0;
         verb(4, "C: %s\n", buf);
         tls_write(srv, buf, l);
      }
      if (FD_ISSET(srv, &fds)) {
         int l;
         unsigned char *buf = tls_read(srv, &l);
         if (buf == NULL)
            break;
         buf[l] = 0;
         verb(4, "S: %s\n", buf);
         sockwrite(cl, buf, l);
         free(buf);
      }
      if (FD_ISSET(fileno(stdin), &fds)) {
         fgets(line, sizeof(line), stdin);
         int m = 0;
         if        (strstr(line, "IV:") == line) {
            m = 0;
            buf += 3;
         } else if (strstr(line, "RL:") == line) {
            m = 1;
            buf += 3;
         } else if (strstr(line, "CT:") == line) {
            m = 2;
            buf += 3;
         }
         if (buf[0] == '@') {
            buf[strlen(buf)-1] = 0;
            addfile(buf+1, m);
            verb(1, "> CH-%d FILE: %s\n", m, buf);
         } else {
            verb(1, "> CH-%d MSG : %s", m, buf);
            addmessage(buf, m);
         }
      }
   }

   close(srv);
   close(cl);
}

/* function main (argc, argv)
 * The entry point into this program.
 * argc - number of arguments
 * argv - the argument vector
 * returns: status code
 */
int main (int argc, char **argv) {
   char *host = NULL;
   char *service = "443", method = 0;
   char c;

   // Don't signal on write error (broken pipe)
   signal(SIGPIPE, SIG_IGN);

   // Initialize the random number generator
   srand(time(NULL)+getpid());

   while ((c = getopt (argc, argv, "h:p:f:m:s:x:d:k:vqt")) != -1) {
      switch (c) {
         case 'h':
            // The host to connect to
            host = optarg;
            if (!servername)
               servername = host;
            break;
         case 'p':
            // The service (443 is default)
            service = optarg;
            break;
         case 's':
            // Server name for SNI
            servername = strdup(optarg);
            break;
         case 'f':
            // Read covert data with the
            // currently chosen method
            addfile(optarg, method);
            break;
         case 'd':
            // Read covert data with the
            // currently chosen method
            addmessage(optarg, method);
            break;
         case 'm':
            // Set the method used for subsequent
            // "-f" or "-d" arguments
            if (!strcasecmp(optarg, "iv")) {
               method = 0;
            } else if (!strcasecmp(optarg, "rl")) {
               method = 1;
            } else if (!strcasecmp(optarg, "ct")) {
               method = 2;
            } else {
               verb(0, "Error: Unknown method '%s'\n", optarg);
               usage();
            }
            break;
         case 'v':
            // Increase verbosity
            verbosity++;
            break;
         case 't':
            // Try STARTTLS
            starttls++;
            break;
         case 'q':
            // Be quiet
            quiet = 1;
            break;
         case 'x':
            // proxy mode
            proxyport = optarg;
            break;
         case 'k':
            // A pre-shared key to XOR the masterseed with
            key = strtol(optarg, 0, 10);
            break;
         default:
            // Argument parse error: print usage and exit
            usage();
      }
   }

   // At least the hostname has to be specified.
   if (host == NULL)
      usage();

   // Generate the master seed and the
   // seeds for the iv and record length methods.
   unsigned int tmpseed = masterseed = rand();
   verb(3, "Using masterseed %08X and key %08X\n", masterseed, key);
   tmpseed ^= key;
   ivseed = rand_r(&tmpseed);
   rlseed = rand_r(&tmpseed);
   ctseed = rand_r(&tmpseed);


   int time = timems();

   if (proxyport) {
      // Open proxy port and wait for connection
      do_proxy_request(proxyport, host, service);
   } else {	
      // Perform an HTTPS request
      do_https_request(host, service);
   }

   // Calculate the total time spent with the connection
   time = timems() - time; 

   // Total number of covert bytes transferred
   int covertbytessent = ivencoff + rlencoff + ctencoff;
   int covertbytespending = ivenclen + rlenclen + ctenclen - covertbytessent;

   // Calculate statistics
   double cbandwidth = covertbytessent*8;
   cbandwidth /= time;
   double tbandwidth = totalbytes*8;
   tbandwidth /= time;
   double cperc = cbandwidth*100/tbandwidth;

   // Print statistics
   verb(0, "Time elapsed             : %d ms\n", time);
   verb(0, "Total  bytes transmitted : %d bytes\n", totalbytes);
   verb(0, "Covert bytes transmitted : %d bytes\n", covertbytessent);
   verb(0, "Covert bytes pending     : %d bytes\n", covertbytespending);
   verb(0, "Total          bandwidth : %.2f kbit/s\n", tbandwidth);
   verb(0, "Covert channel bandwidth : %.2f kbit/s\n", cbandwidth);
   verb(0, "Covert channel percentage: %.2f%%\n", cperc);

   // Print CSV version of statistics
   fprintf(stdout, "%d,%d,%d,%d,%d,%d,%d\n", time, totalbytes, covertbytessent, covertbytespending, ivenclen, rlenclen, ctenclen);
	
   exit(EXIT_SUCCESS);
}


// vim: ts=3:sw=3:et
