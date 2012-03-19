/*
 *
 * (C) 2005-12 - Luca Deri <deri@ntop.org>
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

#include "pfring.h"

#define ALARM_SLEEP             1

pfring  *pd1, *pd2;
pfring_stat pfringStats;
char *in_dev = NULL, *out_dev = NULL;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
#ifdef HAVE_NITRO
pfring_bounce bounce;
#endif

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

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  double thpt;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes = numBytes;
  nPkts  = numPkts;

  {
    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "---\nAbsolute Stats: %s pkts - %s bytes", 
	    pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	    pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

    if(print_all)
      fprintf(stderr, " [%s pkt/sec - %s Mbit/sec]\n",
	      pfring_format_numbers((double)(nPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(thpt, buf2, sizeof(buf2), 1));
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = nPkts-lastPkts;
      bytesDiff = nBytes - lastBytes;
      bytesDiff /= (1000*1000*1000)/8;

      fprintf(stderr, "Actual Stats: %llu pkts [%s ms][%s pps/%s Gbps]\n",
	      (long long unsigned int)diff,
	      pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	      pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1)
	      );
    }

    lastPkts = nPkts, lastBytes = nBytes;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown) {
    exit(0);
  }

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;

#ifdef HAVE_NITRO
  pfring_bounce_breakloop(&bounce);
#else
  pfring_breakloop(pd1);
#endif
}

/* *************************************** */

void printHelp(void) {
 printf("pfdnabounce - (C) 2011-12 ntop.org\n\n");

  printf("pfdnabounce [-v] [-a] -i in_dev\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (RX)\n");
  printf("-o <device>     Device name (TX)\n");
  printf("-v              Verbose\n");
  printf("-a              Active packet wait\n");
  exit(0);
}

/* *************************************** */


int dummyProcesssPacketNitro(u_int16_t pkt_len, u_char *pkt, const u_char *user_bytes) {
  numPkts++;
  numBytes += pkt_len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;

  return 0; /* bounce back */
}

/* *************************************** */

void dummyProcesssPacket(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) { 
  /* Bounce back */
  pfring_send(pd2, (char*)p, h->caplen, 0 /* !flush out */);

  numPkts++;
  numBytes += h->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */; 
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  int promisc;
  u_int32_t version;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"hai:o:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();      
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'o':
      out_dev = strdup(optarg);
      break;
    }
  }

  if(in_dev == NULL)  printHelp();
  if(out_dev == NULL) out_dev = strdup(in_dev);

  printf("Bouncing packets from %s to %s\n", in_dev, out_dev);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  pd1 = pfring_open(in_dev, 1500 /* snaplen */, PF_RING_PROMISC);
  if(pd1 == NULL) {
    printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
    return(-1);
  }

  pfring_version(pd1, &version);
  printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
	 (version & 0x0000FF00) >> 8, version & 0x000000FF);

  pfring_set_application_name(pd1, "pfdnabounce");

  pd2 = pfring_open(out_dev, 1500 /* snaplen */, PF_RING_PROMISC);
  if(pd2 == NULL) {
    printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
    return(-1);
  } 
  
  pfring_set_application_name(pd2, "pfdnabounce");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

#ifdef HAVE_NITRO
  if (pfring_bounce_init(&bounce, pd1, pd2) == 0) {
    printf("Using PF_RING zero-copy library\n");
    pfring_bounce_loop(&bounce, dummyProcesssPacketNitro, (u_char *) NULL, wait_for_packet);
    pfring_bounce_destroy(&bounce);
    goto end;
  }
#endif

  printf("Using PF_RING 1-copy library\n");
  pfring_set_direction(pd1, rx_only_direction);
  pfring_set_direction(pd2, tx_only_direction);

  pfring_enable_ring(pd1);
  pfring_enable_ring(pd2);

  pfring_loop(pd1, dummyProcesssPacket, (u_char*) NULL, wait_for_packet);
#ifdef HAVE_NITRO
 end:
#endif
  pfring_close(pd1);
  pfring_close(pd2);

  sleep(3);

  return(0);
}
