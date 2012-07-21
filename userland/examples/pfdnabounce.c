/*
 *
 * (C) 2005-12 - Luca Deri <deri@ntop.org>
 *               Alfredo Cardigliano <cardigliano@ntop.org>
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
int in_ifindex, out_ifindex;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pfring_dna_bouncer *bouncer_handle = NULL;
int mode = 0;
int bidirectional = 0;
int cluster_id = -1;
int flush = 0;

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

int bind2core(u_int core_id) {
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
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

  switch (mode) {
  case 0: 
    pfring_dna_bouncer_breakloop(bouncer_handle); 
  break;
  case 1:
  case 2: 
    pfring_breakloop(pd1);
  break;
  }
}

/* *************************************** */

void printHelp(void) {
 printf("pfdnabounce - (C) 2011-12 ntop.org\n");
 printf("\nForward traffic from -a -> -b device using DNA\n\n");

  printf("pfdnabounce [-v] [-a] -i in_dev\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (RX)\n");
  printf("-o <device>     Device name (TX)\n");
  printf("-m <mode>       Specifies the library support to use\n"
	 "                0 - DNA Bouncer (default)\n"
	 "                1 - DNA Cluster (use -c <id>)\n"
	 "                2 - Standard DNA\n");
  printf("-c <id>         DNA Cluster id\n");
  printf("-b              Bridge mode: forward in both directions (DNA Cluster and Bouncer only)\n");
  printf("-f              Flush packets immediately (do not use watermarks)\n");
  printf("-g <core id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  exit(0);
}

/* *************************************** */

int dummyProcessPacketZero(u_int16_t pkt_len, u_char *pkt, const u_char *user_bytes) {
  numPkts++;
  numBytes += pkt_len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;

  return DNA_BOUNCER_PASS;
}

/* *************************************** */

void packetConsumerLoopZeroCluster() { 
  struct pfring_pkthdr h;
  int tx_ifindex;
  pfring_pkt_buff *pkt_handle = NULL;

  memset(&h, 0, sizeof(h));

  if ((pkt_handle = pfring_alloc_pkt_buff(pd1)) == NULL) {
    printf("Error allocating pkt buff\n");
    return;
  }

  while (!do_shutdown) {
    if (pfring_recv_pkt_buff(pd1, pkt_handle, &h, wait_for_packet) > 0) {

      if (bidirectional && h.extended_hdr.if_index == in_ifindex)
        tx_ifindex = out_ifindex;
      else if (bidirectional && h.extended_hdr.if_index == out_ifindex)
        tx_ifindex = in_ifindex;
      else if (!bidirectional && h.extended_hdr.if_index == in_ifindex)
        tx_ifindex = out_ifindex;
      else {
        /* unexpected packet, skipping */
        printf("Unexpected packet from interface %d: skipping\n", h.extended_hdr.if_index);
        continue;
      }

      if (pfring_set_pkt_buff_ifindex(pd1, pkt_handle, tx_ifindex) == PF_RING_ERROR_INVALID_ARGUMENT) {
        printf("Wrong interface id: skipping packet\n");
        continue;
      }

      pfring_send_pkt_buff(pd1, pkt_handle, flush);
    }

    numPkts++;
    numBytes += h.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */; 
  }
}

/* *************************************** */

void dummyProcessPacket(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) { 
  
  pfring_send(pd2, (char*)p, h->caplen, flush);

  numPkts++;
  numBytes += h->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */; 
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  int bind_core = -1;
  char buf[32];
  u_int32_t version;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"hai:o:m:bc:g:f")) != -1) {
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
    case 'm':
      mode = atoi(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'b':
      bidirectional = 1;
      break;
    case 'f':
      flush = 1;
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    }
  }

  if (in_dev == NULL)  printHelp();
  if (out_dev == NULL) out_dev = strdup(in_dev);
  if (mode < 0 || mode > 2) printHelp();
  if (bidirectional && mode != 0 && mode != 1) printHelp();
  if (bidirectional && strcmp(in_dev, out_dev) == 0) printHelp();
  if (mode == 1 && cluster_id < 0) printHelp();

  printf("Bouncing packets from %s to %s (%s)\n", in_dev, out_dev, bidirectional ? "two-way" : "one-way");

  switch (mode) {
  case 0:
  case 2:
    pd1 = pfring_open(in_dev, 1500 /* snaplen */, PF_RING_PROMISC);
    if(pd1 == NULL) {
      printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
      return(-1);
    }
    if (!bidirectional)
      pfring_set_socket_mode(pd1, recv_only_mode);

    pd2 = pfring_open(out_dev, 1500 /* snaplen */, bidirectional ? PF_RING_PROMISC : 0);
    if(pd2 == NULL) {
      printf("pfring_open %s error [%s]\n", out_dev, strerror(errno));
      return(-1);
    } 
    if (!bidirectional)
      pfring_set_socket_mode(pd2, send_only_mode);

    pfring_set_application_name(pd2, "pfdnabounce");
  break;

  case 1:
    snprintf(buf, sizeof(buf), "dnacluster:%d", cluster_id);
    pd1 = pfring_open(buf, 1500 /* snaplen */, PF_RING_PROMISC);
    if(pd1 == NULL) {
      printf("pfring_open %s error [%s] (please run \"pfdnacluster_master -i %s,%s -c %d -s\")\n", buf, strerror(errno), in_dev, out_dev, cluster_id);
      return(-1);
    }
    pfring_set_socket_mode(pd1, send_and_recv_mode);
  break;
  }

  pfring_version(pd1, &version);
  printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
         (version & 0x0000FF00) >> 8, version & 0x000000FF);

  pfring_set_application_name(pd1, "pfdnabounce");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  if(bind_core >= 0)
    bind2core(bind_core);

  switch (mode) {
  case 0: 
    printf("Using Libzero DNA Bouncer (zero-copy)\n");

    if ((bouncer_handle = pfring_dna_bouncer_create(pd1, pd2)) == NULL) {
      printf("WARNING: Unable to initialize the DNA Bouncer (ports already in use ?)\n");
      pfring_close(pd1);
      pfring_close(pd2);
      return(-1);
    }
      
    if (bidirectional) {
      if (pfring_dna_bouncer_set_mode(bouncer_handle, two_way_mode) < 0) {
        printf("Error setting the DNA Bouncer to bidirectional\n");
	pfring_dna_bouncer_destroy(bouncer_handle);
	return(-1);
      }
    }

    if(pfring_dna_bouncer_loop(bouncer_handle, dummyProcessPacketZero, (u_char *) NULL, wait_for_packet) == -1) {
      printf("Problems while starting bouncer. See dmesg for details.\n");
    }

    pfring_dna_bouncer_destroy(bouncer_handle);
  break;
  case 1: 
    printf("Using Libzero DNA Cluster (0-copy)\n");

    if (pfring_get_device_ifindex(pd1, in_dev,  &in_ifindex ) < 0 ||
        pfring_get_device_ifindex(pd1, out_dev, &out_ifindex) < 0) {
       printf("Error retrieving interface id\n");
      pfring_close(pd1);
      return(-1);
    }
   
    pfring_enable_ring(pd1);

    packetConsumerLoopZeroCluster();

    pfring_close(pd1);
  break;
  case 2: 
    printf("Using Standard DNA (1-copy)\n");

    pfring_set_direction(pd1, rx_only_direction);
    pfring_set_direction(pd2, tx_only_direction);

    pfring_enable_ring(pd1);
    pfring_enable_ring(pd2);

    pfring_loop(pd1, dummyProcessPacket, (u_char*) NULL, wait_for_packet);

    pfring_close(pd1);
    pfring_close(pd2);
  break;
  }

  sleep(3);

  return(0);
}
