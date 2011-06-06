/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
 *
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "pfring.h"

struct packet {
  u_int16_t len;
  char *pkt;
  struct packet *next;
};

struct packet *pkt_head = NULL;
pfring  *pd;
pfring_stat pfringStats;
char *in_dev = NULL;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
u_int64_t num_pkt_good_sent = 0, last_num_pkt_good_sent = 0;
u_int64_t num_bytes_good_sent = 0, last_num_bytes_good_sent = 0;
struct timeval lastTime, startTime;

#define DEFAULT_DEVICE     "eth0"

typedef unsigned long long ticks;

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* *************************************** */

void print_stats() {
  double deltaMillisec, currentThpt, avgThpt, currentThptBytes, avgThptBytes;
  struct timeval now;

  gettimeofday(&now, NULL);
  deltaMillisec = delta_time(&now, &lastTime);
  currentThpt = (double)((num_pkt_good_sent-last_num_pkt_good_sent) * 1000)/deltaMillisec;
  currentThptBytes = (double)((num_bytes_good_sent-last_num_bytes_good_sent) * 1000)/deltaMillisec;
  currentThptBytes /= (1000*1000*1000)/8;

  deltaMillisec = delta_time(&now, &startTime);
  avgThpt = (double)(num_pkt_good_sent * 1000)/deltaMillisec;
  avgThptBytes = (double)(num_bytes_good_sent * 1000)/deltaMillisec;
  avgThptBytes /= (1000*1000*1000)/8;

  fprintf(stderr, "TX rate: [current %.0f pps/%.3f Gbps][average %.0f pps/%.3f Gbps]\n", 
	  currentThpt, currentThptBytes, avgThpt, avgThptBytes);

  memcpy(&lastTime, &now, sizeof(now));
  last_num_pkt_good_sent = num_pkt_good_sent, last_num_bytes_good_sent = num_bytes_good_sent;
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(1);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();
  printf("Sent %llu packets\n", (long long unsigned int)num_pkt_good_sent);
  pfring_close(pd);

  exit(0);
}

/* *************************************** */

void printHelp(void) {
  printf("pfsend\n(C) 2011 Deri Luca <deri@ntop.org>\n\n");

  printf("pfsend -i out_dev\n");

  printf("-a              Active send re-try\n");
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf("-f <.pcap file> Send packets as read from a pcap file\n");
  printf("-g <core_id>    Bind this app to a code (only with -n 0)\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device\n");
  printf("-l <length>     Packet length to send. Ignored with -f\n");
  printf("-n <num>        Num pkts to send. use 0 for infinite\n");
  printf("-r <rate>       Rate to send (example -r 2.5 sends 2.5 Gbit/sec)\n");
  printf("-v              Verbose\n");
  exit(0);
}

/* *************************************** */

/* Bind this thread to a specific core */

int bind2core(u_int core_id) {
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    printf("Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
}

/* *************************************** */

static __inline__ ticks getticks(void)
{
  unsigned a, d;
  asm("cpuid");
  asm volatile("rdtsc" : "=a" (a), "=d" (d));

  return (((ticks)a) | (((ticks)d) << 32));
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c, *pcap_in = NULL;
  int promisc, i, verbose = 0, active_poll = 0;
  char buffer[1500];
  int send_len = 60;
  u_int32_t num = 1;
  int bind_core = -1;
  u_int16_t cpu_percentage = 0;
  double gbit_s = 0, td, pps;
  ticks tick_start = 0, tick_delta = 0;
  ticks hz = 0;
  struct packet *tosend;

  while((c = getopt(argc,argv,"hi:n:g:l:ab:f:r:v")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'f':
      pcap_in = strdup(optarg);
      break;
    case 'n':
      num = atoi(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'l':
      send_len = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'a':
      active_poll = 1;
      break;
    case 'r':
      sscanf(optarg, "%lf", &gbit_s);
      break;
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    }
  }

  if(in_dev == NULL)  printHelp();

  printf("Sending packets on %s\n", in_dev);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  pd = pfring_open(in_dev, promisc, 1500, 0);
  if(pd == NULL) {
    printf("pfring_open %s error\n", in_dev);
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfdnasend");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if (send_len < 60)
    send_len = 60;

  if(gbit_s > 0) {
    /* cumputing usleep delay */
    tick_start = getticks();
    usleep(1);
    tick_delta = getticks() - tick_start;
    
    /* cumputing CPU freq */
    tick_start = getticks();
    usleep(1001);
    hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
    printf("Estimated CPU freq: %llu Hz\n", hz);

    /* computing max rate */
    pps = ((gbit_s * 1000000000) / 8 /*byte*/) / (8 /*Preamble*/ + send_len + 4 /*CRC*/ + 12 /*IFG*/);

    td = (double)(hz / pps);
    tick_delta = (ticks)td;

    printf("Number of %d-byte Packet Per Second at %.2f Gbit/s: %.2f\n", (send_len + 4 /*CRC*/), gbit_s, pps);
  }


  if(pcap_in) {
    char ebuf[256];
    u_char *pkt;
    struct pcap_pkthdr *h;
    pcap_t *pt = pcap_open_offline(pcap_in, ebuf);

    num = 0;

    if(pt) {
      struct packet *last = NULL;

      while(1) {
	struct packet *p;
	int rc = pcap_next_ex(pt, &h, (const u_char**)&pkt);

	if(rc <= 0) break;

	p = (struct packet*)malloc(sizeof(struct packet));
	if(p) {
	  p->len = h->caplen;
	  p->next = NULL;
	  p->pkt = (char*)malloc(p->len);

	  if(p->pkt == NULL) {
	    printf("Not enough memory\n");
	    break;
	  } else
	    memcpy(p->pkt, pkt, p->len);

	  if(last) {
	    last->next = p;
	    last = p;
	  } else
	    pkt_head = p, last = p;
	} else {
	  printf("Not enough memory\n");
	  break;
	}

	if(verbose) printf("Read %d bytes packet\n", p->len);
	num++;
      } /* while */

      pcap_close(pt);
      printf("Read %d packets\n", num);
      last->next = pkt_head; /* Loop */
      num = 0;
    } else {
      printf("Unable to open file %s\n", pcap_in);
      pfring_close(pd);
      return(-1);
    }
  } else {
    struct packet *p;

    for(i=0; i<send_len; i++) buffer[i] = i;

    p = (struct packet*)malloc(sizeof(struct packet));
    if(p) {
      p->len = send_len;
      p->next = p; /* Loop */
      p->pkt = (char*)malloc(p->len);
      memcpy(p->pkt, buffer, send_len);
      pkt_head = p;
    }
  }

  if(bind_core >= 0)
    bind2core(bind_core);

  if(wait_for_packet && (cpu_percentage > 0)) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(1);
  }

  gettimeofday(&startTime, NULL);

  if (gbit_s > 0)
    tick_start = getticks();

  tosend = pkt_head;
  i = 0;

  while(i <= num) {
    int rc;

  redo:
    rc = pfring_send(pd, tosend->pkt, tosend->len, 0 /* Don't flush (it does PF_RING automatically) */);

    if(verbose)
      printf("[%d] pfring_send(%d) returned %d\n", i, tosend->len, rc);

    if(rc == -1) {
      /* Not enough space in buffer */

      if(gbit_s == 0) {
	if(!active_poll) {
	  if(bind_core >= 0)
	    usleep(1);
	  else
	    pfring_poll(pd, 0);
	}
      } else {
	/* Just waste some time */
	while((getticks() - tick_start) < (i * tick_delta)) ;
      }

      goto redo;
    } else
      num_pkt_good_sent++, num_bytes_good_sent += tosend->len+24 /* 8 Preamble + 4 CRC + 12 IFG */, tosend = tosend->next;

    if(num > 0) i++;
  } /* for */

  print_stats(0);
  pfring_close(pd);

  return(0);
}
