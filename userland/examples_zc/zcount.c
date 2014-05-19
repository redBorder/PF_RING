/*
 *
 * (C) 2014 - ntop.org
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
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <numa.h>

#include "pfring.h"

#include "pfring_zc.h"

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768

#define NBUFF      256 /* pow */
#define NBUFFMASK 0xFF /* 256-1 */

pfring_zc_cluster *zc;
pfring_zc_queue *zq;
pfring_zc_pkt_buff *buffers[NBUFF];
u_int32_t lru = 0;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
int bind_core = -1;
int buffer_len = 1536;
u_int8_t wait_for_packet = 1, do_shutdown = 0, verbose = 0, add_filtering_rule = 0;

/* *************************************** */

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

/* *************************************** */

double delta_time (struct timeval * now, struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;
  
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }

  return ((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastDrops = 0;
  static u_int64_t lastBytes = 0;
  double pktsDiff, dropsDiff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0, nDrops = 0;
  pfring_zc_stat stats;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes = numBytes;
  nPkts = numPkts;
  if (pfring_zc_stats(zq, &stats) == 0)
    nDrops = stats.drop;

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts (%s drops) - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nDrops, buf3, sizeof(buf3), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    pktsDiff = nPkts-lastPkts;
    dropsDiff = nDrops-lastDrops;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    snprintf(buf, sizeof(buf),
	     "Actual Stats: %s pps (%s drops) - %s Gbps",
	     pfring_format_numbers(((double)pktsDiff/(double)(deltaMillisec/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double)dropsDiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
    fprintf(stderr, "%s\n", buf);
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastDrops = nDrops, lastBytes = nBytes;
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(zq);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown) return;

  print_stats();

  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("zcount - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());

  printf("A simple packet counter application.\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  printf("-B              Packet buffer size (default: %d bytes)\n", buffer_len);
  printf("-R              Test hw filters adding a rule (Intel 82599)\n");
  printf("-v              Verbose\n");
  exit(-1);
}

/* *************************************** */

void* packet_consumer_thread(void* _id) {

  if (bind_core >= 0)
    bind2core(bind_core);

  while(!do_shutdown) {
    if(pfring_zc_recv_pkt(zq, &buffers[lru], wait_for_packet) > 0) {

      if (unlikely(verbose)) {
        if (buffers[lru]->ts.tv_nsec)
          printf("[%u.%u] ", buffers[lru]->ts.tv_sec, buffers[lru]->ts.tv_nsec);
#if 1
        char bigbuf[4096];
        pfring_print_pkt(bigbuf, sizeof(bigbuf), buffers[lru]->data, buffers[lru]->len, buffers[lru]->len);
        fputs(bigbuf, stdout);
#else
        int i;
        for(i = 0; i < buffers[lru]->len; i++)
          printf("%02X ", buffers[lru]->data[i]);
        printf("\n");
#endif
      }

      numPkts++;
      numBytes += buffers[lru]->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

      lru++; lru &= NBUFFMASK;
    }

  }

   pfring_zc_sync_queue(zq, rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int i, cluster_id = -1;
  pthread_t my_thread;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:vB:R")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'B':
      buffer_len = atoi(optarg);
      break;
    case 'R':
      add_filtering_rule = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();

  zc = pfring_zc_create_cluster(
    cluster_id, 
    buffer_len,
    0, 
    MAX_CARD_SLOTS + NBUFF,
    numa_node_of_cpu(bind_core),
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check that pf_ring.ko is loaded and hugetlb fs is mounted\n",
	    strerror(errno));
    return -1;
  }

  zq = pfring_zc_open_device(zc, device, rx_only, 0);

  if(zq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	    strerror(errno), device);
    return -1;
  }

  for (i = 0; i < NBUFF; i++) { 

    buffers[i] = pfring_zc_get_packet_handle(zc);

    if (buffers[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }
  }

  if(add_filtering_rule) {
    int rc;
    hw_filtering_rule rule;
    intel_82599_perfect_filter_hw_rule *perfect_rule = &rule.rule_family.perfect_rule;

    memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
    rule.rule_id = 0, perfect_rule->queue_id = -1, perfect_rule->proto = 17, perfect_rule->s_addr = ntohl(inet_addr("10.0.0.1"));

    rc = pfring_zc_add_hw_rule(zq, &rule);

    if(rc != 0)
      printf("pfring_zc_add_hw_rule(%d) failed: did you enable the FlowDirector (ethtool -K ethX ntuple on)\n", rule.rule_id);
    else
      printf("pfring_zc_add_hw_rule(%d) succeeded: dropping UDP traffic 192.168.30.207:* -> *\n", rule.rule_id);
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (!verbose) { /* periodic stats */
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pthread_create(&my_thread, NULL, packet_consumer_thread, (void*) NULL);
  pthread_join(my_thread, NULL);

  sleep(1);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

