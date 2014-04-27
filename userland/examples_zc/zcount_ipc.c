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

pfring_zc_queue *zq;
pfring_zc_buffer_pool *zp;
pfring_zc_pkt_buff *buffer;

static struct timeval startTime;
int bind_core = -1;
int vm_guest = 0;

struct volatile_globals {
  unsigned long long numPkts;
  unsigned long long numBytes;
  int wait_for_packet;
  int verbose;
  volatile int do_shutdown;
};

struct volatile_globals *globals;

/* *************************************** */

int bind2node(int core_id) {
  char node_str[8];

  if (core_id < 0 || numa_available() == -1)
    return -1;

  snprintf(node_str, sizeof(node_str), "%u", numa_node_of_cpu(core_id));
  numa_bind(numa_parse_nodestring(node_str));

  return 0;
}

/* *************************************** */

int bind2core(int core_id) {
  cpu_set_t cpuset;
  int s;

  if (core_id < 0) return -1;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return -1;
  }
  
  return 0;
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

  nBytes = globals->numBytes;
  nPkts = globals->numPkts;
  if (pfring_zc_stats(zq, &stats) == 0)
    nDrops = stats.drop;
  else
    printf("Error reading drop stats\n");

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts (%s drops) - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nDrops, buf2, sizeof(buf2), 0),
	  pfring_format_numbers((double)nBytes, buf3, sizeof(buf3), 0));

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

  globals->do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(zq);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(globals->do_shutdown) return;

  print_stats();

  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("zcount_ipc - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A simple packet counter application consuming packets from a sw queue.\n\n");
  printf("-h              Print this help\n");
  printf("-i <queue id>   Zero queue id\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  printf("-v              Verbose: print packet data\n");
  printf("-u              Guest VM (master on the host)\n");
  exit(-1);
}

/* *************************************** */

void *packet_consumer_thread(void *_id) {
  struct volatile_globals *g = globals;

  bind2core(bind_core);

  while(!g->do_shutdown) {

    if(pfring_zc_recv_pkt(zq, &buffer, g->wait_for_packet) > 0) {

      if (unlikely(g->verbose)) {
        int i;

        if (buffer->ts.tv_nsec)
          printf("[%u.%u] ", buffer->ts.tv_sec, buffer->ts.tv_nsec);

        for(i = 0; i < buffer->len; i++)
          printf("%02X ", buffer->data[i]);
        printf("\n");
      }

      g->numPkts++;
      g->numBytes += buffer->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
    }
  }

   pfring_zc_sync_queue(zq, rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  int cluster_id = -1, queue_id = -1;
  pthread_t my_thread;
  int wait_for_packet = 1, verbose = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:vu")) != '?') {
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
      queue_id = atoi(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'u':
      vm_guest = 1;
      break;
    }
  }
  
  if (cluster_id < 0) printHelp();
  if (queue_id < 0) printHelp();

  bind2node(bind_core);

  /* volatile global variables initialization */
  globals = calloc(1, sizeof(*globals));
  globals->wait_for_packet = wait_for_packet;
  globals->verbose = verbose;
  globals->numPkts = 0;
  globals->numBytes = 0;
  globals->do_shutdown = 0;

  if (vm_guest)
    pfring_zc_vm_guest_init(NULL /* auto */);

  zq = pfring_zc_ipc_attach_queue(cluster_id, queue_id, rx_only);

  if(zq == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  zp = pfring_zc_ipc_attach_buffer_pool(cluster_id, queue_id);

  if(zp == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_buffer_pool error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  buffer = pfring_zc_get_packet_handle_from_pool(zp);

  if (buffer == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle_from_pool error\n");
    return -1;
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  pthread_create(&my_thread, NULL, packet_consumer_thread, (void*) NULL);
  pthread_join(my_thread, NULL);

  sleep(1);

  pfring_zc_release_packet_handle_to_pool(zp, buffer);

  pfring_zc_ipc_detach_queue(zq);
  pfring_zc_ipc_detach_buffer_pool(zp);

  return 0;
}

