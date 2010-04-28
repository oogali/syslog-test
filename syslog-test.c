/*
 * syslog-test:
 *
 * an experiment to build a tokyocabinet-backed databased, powered by
 * libevent, and the goodness of C.
 *
 * we're a single thread for now.
 * @oogali (yes, twitter)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <event.h>
#include <tctdb.h>

#define IPV4_TCP  0x1001
#define IPV4_UDP_DATAGRAM  0x1002
#define IPV4_UDP_SEQUENCE  0x1003
#define IPV4_RAW  0x1004

/*
 * sockets: linked list containing the sockets we are listening to
 *
 * fd: socket file descriptor
 * addr: socket address structure
 * status: perhaps i'll store connected/unconnected state here?
 * event: event structure
 * next: your partner has disconnected
 */
struct sockets {
  int fd;
  struct sockaddr_in addr;
  uint8_t status;
  struct event event;
  struct sockets *next;
};

struct sockets *sock_head = NULL, *sock_tail = NULL;
TCTDB *tdb;

/*
 * open_and_bind: open a socket, and bind to an ip:port
 *
 * socktype: type of socket (tcp, udp, udpseq, raw)
 * ip: string representation of IPv4 address (sorry, no IPv6 yet)
 * port: port we should listen on
 */
struct sockets *open_and_bind(int socktype, char *ip, uint16_t port)
{
  struct sockets *sock = NULL;

  /* allocate memory for socket structure or bomb out */
  sock = calloc(1, sizeof(struct sockets));
  if (sock == NULL) {
    perror("calloc");
    return NULL;
  }

  /* open appropriate socket */
  switch(socktype) {
    case IPV4_TCP:
      sock->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      break;
    case IPV4_UDP_DATAGRAM:
      sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      break;
    case IPV4_UDP_SEQUENCE:
      sock->fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_UDP);
      break;
    case IPV4_RAW:
      sock->fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
      break;
    default:
      fprintf(stderr, "open_and_bind: unsupported socket type\n");
      sock->fd = -1;
  }

  /* no socket? clean up and leave */
  if (sock->fd < 0) {
    perror("socket");
    free(sock);
    return NULL;
  }

  /* zero out our socket address structure, and fill */
  bzero(&sock->addr, sizeof(struct sockaddr));
  switch (socktype) {
    case IPV4_TCP:
    case IPV4_UDP_DATAGRAM:
    case IPV4_UDP_SEQUENCE:
      sock->addr.sin_family = AF_INET;
      sock->addr.sin_addr.s_addr = inet_addr(ip);
      sock->addr.sin_port = htons(port);
      break;
    default:
      fprintf(stderr, "open_and_bind: (memory corruption?)\n");
      free(sock);
      return NULL;
  }

  /* bind to our socket, clean up and leave on failure */
  if (bind(sock->fd, (struct sockaddr *)&sock->addr, sizeof(struct sockaddr)) < 0) {
    perror("bind");
    free(sock);
    return NULL;
  }

  /* we made it, return pointer to our socket structure */
  return sock;
}

/*
 * log_message: log our message to our tokyocabinet table
 *
 * src_ip: string representation of the message source
 * tv: structure containing the time we received this message
 * priority: the priority of this message
 * msg: don't push me, cuz i'm close to the edge;
 *      i'm trying not to lose my head
 */
int log_message(char *src_ip, struct timeval tv, uint16_t priority, char *msg)
{
  char pk[256], ts[64], facility[8], severity[8];
  TCMAP *cols;
 
  /* sanity check */
  if (tdb == NULL) {
    fprintf(stderr, "log_message: looks like database handle isn't initalized!\n");
    return -1;
  }

  /* zero out buffer, generate and store primary key */
  bzero(&pk, sizeof(pk));
  snprintf(pk, sizeof(pk), "%ld", (long)tctdbgenuid(tdb));

  /* zero out buffer, store string representation of timestamp */
  bzero(&ts, sizeof(ts));
  snprintf(ts, sizeof(ts), "%ld.%09ld", tv.tv_sec, tv.tv_usec);

  /* zero out buffer, store facility code */
  bzero(&facility, sizeof(facility));
  snprintf(facility, sizeof(facility), "%d", priority / 8);

  /* zero out buffer, store severity code */
  bzero(&severity, sizeof(severity));
  snprintf(severity, sizeof(severity), "%d", priority % 8);

  /* create database table row, or leave on error*/
  cols = tcmapnew3("ts", ts, "src", src_ip, "facility", facility, "severity", severity, "msg", msg, NULL);
  if (cols == NULL) {
    fprintf(stderr, "could not create tc map\n");
    return -1;
  }

  /* store row in the table, or clean up and leave */
  if (!tctdbput(tdb, pk, strlen(pk), cols)) {
    fprintf(stderr, "could not store row in db: %s\n", tctdberrmsg(tctdbecode(tdb)));
    tcmapdel(cols);
    return -1;
  }

  /* success, clean up */
  tcmapdel(cols);

  return 0;
}

/*
 * read_socket_data: read incoming message off the socket fd
 *
 * fd: socket file descriptor we're reading from
 * event_type: the type of event that got us here
 * s: our socket structure
 */
void read_socket_data(int fd, short event_type, void *s)
{
  struct sockets *sock = (struct sockets *)s;
  char src_ipaddr[INET_ADDRSTRLEN], dst_ipaddr[INET_ADDRSTRLEN];
  uint16_t src_port, dst_port;
  char buf[1024];
  char *end;
  struct sockaddr_in src;
  uint32_t srclen = sizeof(struct sockaddr);
  long len = 0;
  int i = 0;
  uint16_t priority = 0;
  struct timeval tv;

  /* sanity check, in case of memory corruption */
  if (s == NULL) {
    fprintf(stderr, "incoming socket structure is null!\n");
    return;
  }

  /* timestamp when we entered this block */
  if (gettimeofday(&tv, NULL) < 0) {
    perror("gettimeofday");
    return;
  }

  /* convert destination ip to string representation, flip port from network to host order */
  if (inet_ntop(AF_INET, &sock->addr.sin_addr, dst_ipaddr, sizeof(struct sockaddr)) == NULL) {
    fprintf(stderr, "could not convert IP to string\n");
    return;
  }
  dst_port = ntohs(sock->addr.sin_port);

  /* zero out buffers in preparation for data */
  bzero(&buf, sizeof(buf));
  bzero(&src, sizeof(struct sockaddr));

  /* read data from socket */
  if ((len = recvfrom(sock->fd, &buf, sizeof(buf), 0, (struct sockaddr *)&src, &srclen)) < 0) {
    perror("recvfrom");
    return;
  }

  /* convert source ip to string representation, flip port from network to host order */
  if (inet_ntop(AF_INET, &src.sin_addr, src_ipaddr, sizeof(struct sockaddr)) == NULL) {
    fprintf(stderr, "could not convert IP to string\n");
    return;
  }
  src_port = ntohs(src.sin_port);

  /* i should probably remove this... a flurry of messages will cause printf to eat cpu */
  printf("received %ld bytes from %s:%d to %s:%d\n", len, src_ipaddr, src_port, dst_ipaddr, dst_port);

  /* walk string, find priority, convert to long */
  if (buf[0] == '<') {
    while(i < sizeof(buf) && buf[i] != '>') {
      i++;
    }
    
    if (i >= sizeof(buf)) {
      /* end of buffer reached without finding '>' */
      break;
    }

    end = buf + i;
    priority = strtol(buf + 1, &end, 10);
  }

  /* did we get a valid priority? */
  if (priority == -1) {
    printf("couldn't find priority in %ld-byte message from %s:%d to %s:%d\n", len, src_ipaddr, src_port, dst_ipaddr, dst_port);
    return;
  }

  /* log the message */
  if (log_message(src_ipaddr, tv, priority, buf + i + 1) < 0) {
    fprintf(stderr, "error logging message...continuing\n");
  }
}

/*
 * break_signal_handler: catch signals and interrupt event loop
 *
 * nothing too fancy here, we simply exit the event loop, and continue
 * through the end of main()
 */
void break_signal_handler(int signo)
{
  event_loopexit(NULL);
}

/*
 * yeah, the big kahuna.
 */
int main(int argc, char **argv)
{
  int i;
  uint16_t port;
  struct sockets *sock = NULL;
  struct event_base *eb = NULL;
  char ipaddr[INET_ADDRSTRLEN];

  if (argc < 3) {
    fprintf(stderr, "%s <ip1> <port1> [ip2] [port2] ...\n", argv[0]);
    return -1;
  }

  /* create our tokyocabinet database handle */
  tdb = tctdbnew();
  if (tdb == NULL) {
    fprintf(stderr, "%s: could not initialize tc table handler\n", argv[0]);
    return -1;
  }

  /* open our database for reading */
  if (!tctdbopen(tdb, "syslog.tct", TDBOWRITER | TDBOCREAT)) {
    fprintf(stderr, "%s: error opening syslog table: %s\n", argv[0], tctdberrmsg(tctdbecode(tdb)));
    return -1;
  }

  /* loop through command line arguments, open sockets */
  for (i = 1; i < argc; i += 2) {
    strncpy(ipaddr, argv[i], sizeof(ipaddr));
    port = atoi(argv[i + 1]);

    sock = open_and_bind(IPV4_UDP_DATAGRAM, ipaddr, port);
    if (sock == NULL) {
      fprintf(stderr, "%s: could not bind to requested address\n", argv[0]);
      return -1;
    }

    if (sock_head == NULL) {
      sock_head = sock_tail = sock;
    } else {
      sock_tail->next = sock;
      sock_tail = sock;
    }
  }

  /* initialize our libevent base */
  eb = event_init();
  if (eb == NULL) {
    fprintf(stderr, "%s: could not initialize event base\n", argv[0]);
    return -1;
  }

  /* walk through our sockets list, add to event list */
  sock = sock_head;
  while (sock != NULL) {
    event_set(&sock->event, sock->fd, EV_READ | EV_PERSIST, (void *)&read_socket_data, sock);
    event_add(&sock->event, NULL);
    sock = sock->next;
  }

  /* install our signal handler, right now we only care about ctrl+c */
  if (signal(SIGINT, break_signal_handler) == SIG_ERR) {
    perror("signal");
    return -1;
  }

  /* start the event loop, we should only exit this if interrupted */
  printf("starting event loop using %s\n", event_base_get_method(eb));
  event_dispatch();

  /* close our tokyocabinet database */
  if (!tctdbclose(tdb)) {
    fprintf(stderr, "%s: could not close db: %s\n", argv[0], tctdberrmsg(tctdbecode(tdb)));
    return -1;
  }

  return 0;
}
