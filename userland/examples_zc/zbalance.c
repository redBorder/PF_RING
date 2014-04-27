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
#define PREFETCH_BUFFERS        8
#define QUEUE_LEN            8192

#define VERY_VERBOSE

struct stats {
  u_int64_t __cache_line_padding_p[8];
  u_int64_t numPkts;
  u_int64_t numBytes;
  u_int64_t __cache_line_padding_a[5];
  volatile u_int64_t do_shutdown;
};

pfring_zc_cluster *zc;
pfring_zc_worker *zw;
pfring_zc_queue **inzq;
pfring_zc_queue **outzq;
pfring_zc_multi_queue *outzmq; /* fanout */
pfring_zc_buffer_pool *wsp;

pfring_zc_pkt_buff **buffers;

u_int32_t num_devices = 0;
u_int32_t num_threads = 0;
int *bind_core = NULL;
int bind_worker_core = -1;
char **devices = NULL;

static struct timeval startTime;
u_int8_t wait_for_packet = 1, do_shutdown = 0;

struct stats *consumers_stats;

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
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  int i;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

#ifdef VERY_VERBOSE
  fprintf(stderr, "=========================\n");
#endif
  for (i = 0; i < num_threads; i++) {
#ifdef VERY_VERBOSE
  fprintf(stderr, "Thread #%u: %s pkts - %s bytes\n", i,
	  pfring_format_numbers((double)consumers_stats[i].numPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)consumers_stats[i].numBytes, buf2, sizeof(buf2), 0));
#endif
    nPkts  += consumers_stats[i].numPkts;
    nBytes += consumers_stats[i].numBytes;
  }

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    diff = nPkts-lastPkts;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    snprintf(buf, sizeof(buf),
	     "Actual Stats: %s pps - %s Gbps",
	     pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
    fprintf(stderr, "%s\n", buf);
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastBytes = nBytes;
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  int i;
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  for (i = 0; i < num_threads; i++) {
    consumers_stats[i].do_shutdown = 1;
    pfring_zc_queue_breakloop(outzq[i]);
  }
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
  printf("zbalance - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A master thread balancing packets to multiple consumer threads counting packets.\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (comma-separated list)\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-m <hash mode>  Hashing modes:\n"
         "                0 - No hash: Round-Robin (default)\n"
         "                1 - IP hash\n"
         "                2 - Fan-out\n");
  printf("-r <id>         Balancer thread core affinity\n");
  printf("-g <id:id...>   Consumer threads core affinity mask\n");
  printf("-a              Active packet wait\n");
  exit(-1);
}

/* *************************************** */

void* consumer_thread(void* _id) {
  long id = (long) _id;

  pfring_zc_pkt_buff *b = buffers[id];

  bind2core(bind_core[id]);

  while(!consumers_stats[id].do_shutdown) {

    if(pfring_zc_recv_pkt(outzq[id], &b, wait_for_packet) > 0) {

#if 0
      int i;

      for(i = 0; i < b->len; i++)
        printf("%02X ", b->data[i]);
      printf("\n");
#endif

      consumers_stats[id].numPkts++;
      consumers_stats[id].numBytes += b->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
    }

  }

  pfring_zc_sync_queue(outzq[id], rx_only);

  return NULL;
}

/* *************************************** */

static int rr = 0;

int32_t rr_distribution_func(pfring_zc_pkt_buff *pkt_handle, void *user) {
  long num_out_queues = (long) user;
  return rr++ % num_out_queues;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *dev, c;
  long i;
  int cluster_id = -1;
  char *bind_mask = NULL;
  pthread_t *threads;
  char *id;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  int hash_mode = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:r:m:")) != '?') {
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
    case 'm':
      hash_mode = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    case 'r':
      bind_worker_core = atoi(optarg);
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();
  if (bind_mask == NULL) printHelp();

  id = strtok(bind_mask, ":");
  while(id != NULL) {
    bind_core = realloc(bind_core, sizeof(int) * (num_threads+1));
    bind_core[num_threads] = atoi(id) % numCPU;
    num_threads++;
    id = strtok(NULL, ":");
  }
  if (num_threads < 1) printHelp();

  dev = strtok(device, ",");
  while(dev != NULL) {
    devices = realloc(devices, sizeof(char *) * (num_devices+1));
    devices[num_devices] = strdup(dev);
    num_devices++;
    dev = strtok(NULL, ",");
  }

  zc = pfring_zc_create_cluster(
    cluster_id, 
    1536,
    0,
    (num_devices * MAX_CARD_SLOTS) + (num_threads * QUEUE_LEN) + num_threads + PREFETCH_BUFFERS,
    numa_node_of_cpu(bind_worker_core), 
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  threads = calloc(num_threads,     sizeof(pthread_t));
  buffers = calloc(num_threads,     sizeof(pfring_zc_pkt_buff *));
  inzq =    calloc(num_devices,     sizeof(pfring_zc_queue *));
  outzq =   calloc(num_threads,     sizeof(pfring_zc_queue *));
  consumers_stats = calloc(num_threads, sizeof(struct stats));

  for (i = 0; i < num_threads; i++) { 
    buffers[i] = pfring_zc_get_packet_handle(zc);

    if (buffers[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }
  }

  for (i = 0; i < num_devices; i++) {
    inzq[i] = pfring_zc_open_device(zc, devices[i], rx_only, 0);

    if(inzq[0] == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), devices[i]);
      return -1;
    }
  }

  for (i = 0; i < num_threads; i++) { 
    outzq[i] = pfring_zc_create_queue(zc, QUEUE_LEN);

    if(outzq[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
      return -1;
    }
  }

  wsp = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);

  if (wsp == NULL) {
    fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
    return -1;
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  printf("Starting balancer with %d consumer threads..\n", num_threads);

  if (hash_mode < 2) { /* balancer */

    zw = pfring_zc_run_balancer(
      inzq, 
      outzq, 
      num_devices, 
      num_threads, 
      wsp,
      round_robin_bursts_policy, 
      NULL /* idle callback */,
      hash_mode == 0 ? rr_distribution_func : NULL /* build-in IP-based  */, 
      (void *) ((long) num_threads),
      !wait_for_packet, 
      bind_worker_core
    );

  } else {

    outzmq = pfring_zc_create_multi_queue(outzq, num_threads);

    if(outzmq == NULL) {
      fprintf(stderr, "pfring_zc_create_multi_queue error [%s]\n", strerror(errno));
      return -1;
    }

    zw = pfring_zc_run_fanout(
      inzq, 
      outzmq, 
      num_devices,
      wsp,
      round_robin_bursts_policy, 
      NULL /* idle callback */,
      NULL /* built-in send-to-all */, 
      (void *) ((long) num_threads),
      !wait_for_packet, 
      bind_worker_core
    );

  }

  if(zw == NULL) {
    fprintf(stderr, "pfring_zc_run_balancer error [%s]\n", strerror(errno));
    return -1;
  }

  for (i = 0; i < num_threads; i++)
    pthread_create(&threads[i], NULL, consumer_thread, (void*) i);
  
  for (i = 0; i < num_threads; i++)
    pthread_join(threads[i], NULL);

  pfring_zc_kill_worker(zw);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

