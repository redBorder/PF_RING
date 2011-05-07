/*
 *
 * (C) 2005-10 - Luca Deri <deri@ntop.org>
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
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

#define ENABLE_DNA_SUPPORT

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       128
#define MAX_NUM_THREADS        64

int verbose = 0, num_channels = 1;
pfring_stat pfringStats;

static struct timeval startTime;
pfring  *ring[MAX_NUM_THREADS] = { NULL };
unsigned long long numPkts[MAX_NUM_THREADS] = { 0 }, numBytes[MAX_NUM_THREADS] = { 0 };
u_int8_t wait_for_packet = 1,  do_shutdown = 0, dna_mode = 0;
pthread_t pd_thread[MAX_NUM_THREADS];

#define DEFAULT_DEVICE     "eth0"

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
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int64_t lastPkts[MAX_NUM_THREADS] = { 0 };
  u_int64_t diff;
  static struct timeval lastTime;
  int i;
  unsigned long long nBytes = 0, nPkts = 0, pkt_dropped = 0;
  unsigned long long nPktsLast = 0;
  double pkt_thpt = 0, delta;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  delta = delta_time(&endTime, &lastTime);

  for(i=0; i < num_channels; i++) {
    nBytes += numBytes[i], nPkts += numPkts[i];
  
    if(pfring_stats(ring[i], &pfringStat) >= 0) {
      double thpt = ((double)8*numBytes[i])/(deltaMillisec*1000);

      fprintf(stderr, "=========================\n"
	      "Absolute Stats: [channel=%d][%u pkts rcvd][%u pkts dropped]\n"
	      "Total Pkts=%u/Dropped=%.1f %%\n",
	      i, (unsigned int)numPkts[i], (unsigned int)pfringStat.drop,
	      (unsigned int)(numPkts[i]+pfringStat.drop),
	      numPkts[i] == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(numPkts[i]+pfringStat.drop));
      fprintf(stderr, "%llu pkts - %llu bytes", numPkts[i], numBytes[i]);
      fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n", (double)(numPkts[i]*1000)/deltaMillisec, thpt);
      pkt_dropped += pfringStat.drop;

      if(lastTime.tv_sec > 0) {
	double pps;
	
	diff = numPkts[i]-lastPkts[i];
	nPktsLast += diff;
	pps = ((double)diff/(double)(delta/1000));
	fprintf(stderr, "=========================\n"
		"Actual Stats: [channel=%d][%llu pkts][%.1f ms][%.1f pkt/sec]\n",
		i, (long long unsigned int)diff, delta, pps);
	pkt_thpt += pps;
      }


      lastPkts[i] = numPkts[i];
    }
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
  fprintf(stderr, "Aggregate stats (all channels): [%.1f pkt/sec][%llu pkts dropped]\n", 
	  (double)(nPktsLast*1000)/(double)delta, pkt_dropped);
  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
#if 0
  int i;
#endif

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

#if 0
  for(i=0; i<num_channels; i++) {
    pthread_join(pd_thread[i], NULL);
    pfring_close(ring[i]);
  }
#endif

  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount_multichannel\n(C) 2005-11 Deri Luca <deri@ntop.org>\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (No device@channel)\n");

  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-l <len>        Capture length\n");
  printf("-w <watermark>  Watermark\n");
  printf("-p <poll wait>  Poll wait (msec)\n");
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf("-a              Active packet wait\n");
  printf("-r              Rehash RSS packets\n");
  printf("-v              Verbose\n");
}

/* *************************************** */

void* packet_consumer_thread(void* _id) {
  int s;
  long thread_id = (long)_id; 
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  u_long core_id = thread_id % numCPU;
 
  if(numCPU > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      printf("Error while binding thread %ld to core %ld: errno=%i\n", 
	     thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
  }

  while(1) {
    u_char buffer[2048];
    struct pfring_pkthdr hdr;

    if(do_shutdown) break;

    if(pfring_recv(ring[thread_id], (char*)buffer, sizeof(buffer), &hdr, wait_for_packet) > 0) {
      if(do_shutdown) break;
      numPkts[thread_id]++, numBytes[thread_id] += hdr.len;
    } else {
      // if(wait_for_packet == 0) sched_yield();
      //usleep(1);
    }
  }

  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int promisc, snaplen = DEFAULT_SNAPLEN, rc, watermark = 0, rehash_rss = 0;
  packet_direction direction = rx_and_tx_direction;
  pfring  *pd = NULL;
  long i;
  u_int16_t cpu_percentage = 0, poll_duration = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"hi:l:vae:w:b:rp:d" /* "f:" */)) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'e':
      switch(atoi(optarg)) {
      case rx_and_tx_direction:
      case rx_only_direction:
      case tx_only_direction:
	direction = atoi(optarg);
	break;
      }
      break;
    case 'd':
#ifdef ENABLE_DNA_SUPPORT
      dna_mode = 1;
#endif
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    case 'r':
      rehash_rss = 1;
      break;
    case 'p':
      poll_duration = atoi(optarg);
      break;
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;

  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  if(!dna_mode)
    pd = pfring_open(device, promisc,  snaplen, 0);
#ifdef ENABLE_DNA_SUPPORT
    pd = pfring_open_dna(device, promisc, 0 /* we don't use threads */);    
#endif  
  
  if(pd == NULL) {
    printf("pfring_open error (%s)\n", device);
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfcount");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }
  
  num_channels = pfring_get_num_rx_channels(pd);
  printf("# Device RX channels: %d\n", pfring_get_num_rx_channels(pd));
  pfring_close(pd);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);


  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  printf("Spawning %d threads, one per channel, each bound to a different core\n", num_channels);

  for(i=0; i<num_channels; i++) {
    char devname[64];
    
    snprintf(devname, sizeof(devname), "%s@%ld", device, i);

  if(!dna_mode)
    ring[i] = pfring_open(device, promisc,  snaplen, 0);
#ifdef ENABLE_DNA_SUPPORT
  ring[i] = pfring_open_dna(device, promisc, 0 /* we don't use threads */);    
#endif  
    
    if(ring[i] == NULL) {
      printf("pfring_open error\n");
      return(-1);
    } else {
      char buf[32];

      snprintf(buf, sizeof(buf), "pfcount_multichannel-thread %ld", i);
      pfring_set_application_name(ring[i], buf);
    }

    if(!dna_mode) {
      if((rc = pfring_set_direction(ring[i], direction)) != 0)
	printf("pfring_set_direction returned [rc=%d][direction=%d]\n", rc, direction);
      
      if(watermark > 0) {
	if((rc = pfring_set_poll_watermark(pd, watermark)) != 0)
	  printf("pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
      }

    if(rehash_rss)
      pfring_enable_rss_rehash(ring[i]);
    }

    if(poll_duration > 0)
      pfring_set_poll_duration(ring[i], poll_duration);

    pfring_enable_ring(ring[i]);

    pthread_create(&pd_thread[i], NULL, packet_consumer_thread, (void*)i);
  }

  if(cpu_percentage > 0) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }
  
  for(i=0; i<num_channels; i++)
    pthread_join(pd_thread[i], NULL);

  return(0);
}
