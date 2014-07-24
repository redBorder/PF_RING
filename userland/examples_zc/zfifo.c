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

#include "zutils.c"

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768
#define PREFETCH_BUFFERS       32
#define QUEUE_LEN            8192

#define VERY_VERBOSE

struct stats {
  u_int64_t __cache_line_padding_p[8];
  u_int64_t tot_recv;
  u_int64_t tot_bytes;
  u_int64_t __cache_line_padding_a[6];
};

pfring_zc_cluster *zc;
pfring_zc_worker *zw;
pfring_zc_queue **inzq;
pfring_zc_queue *outzq;
pfring_zc_buffer_pool *wsp;

pfring_zc_pkt_buff *buffer;

u_int32_t num_devices = 0;
int bind_worker_core = -1;
int bind_timer_core = -1;
int bind_consumer_core = -1;
char **devices = NULL;

struct timeval startTime;
u_int8_t wait_for_packet = 1;
volatile u_int8_t do_shutdown = 0;

struct stats consumers_stats;

/* ******************************** */

void print_stats() {
  struct timeval end_time;
  double delta_msec;
  static u_int8_t print_all;
  static u_int64_t last_tot_recv = 0;
  static u_int64_t last_tot_bytes = 0;
  static u_int64_t last_tot_drop = 0;
  double diff_recv, diff_bytes, diff_drop;
  static struct timeval last_time;
  char buf1[64], buf2[64];
  unsigned long long tot_bytes = 0, tot_recv = 0, tot_drop = 0;
  pfring_zc_stat stats;
  int i;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&end_time, NULL);
  delta_msec = delta_time(&end_time, &startTime);

  for (i = 0; i < num_devices; i++)
    if (pfring_zc_stats(inzq[i], &stats) == 0)
      tot_recv += stats.recv, tot_drop += stats.drop;

  tot_bytes = consumers_stats.tot_bytes;

  fprintf(stderr, "=========================\n"
	  "FIFO Stats: %s pkts (%s drops)\n", 
	  pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)tot_drop, buf2, sizeof(buf2), 0));

#ifdef VERY_VERBOSE
  fprintf(stderr, "Consumer Stats: %s pkts - %s bytes",
	  pfring_format_numbers((double)consumers_stats.tot_recv, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)consumers_stats.tot_bytes, buf2, sizeof(buf2), 0));
#endif

  if(print_all && (last_time.tv_sec > 0)) {
    delta_msec = delta_time(&end_time, &last_time);
    diff_recv = tot_recv-last_tot_recv;
    diff_bytes = tot_bytes - last_tot_bytes;
    diff_bytes /= (1000*1000*1000)/8;
    diff_drop = tot_drop-last_tot_drop;

    fprintf(stderr, " (%s Gbps)\n", pfring_format_numbers(((double)diff_bytes/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1));

    fprintf(stderr, "Actual FIFO Stats: %s pps (%s drops)",
	    pfring_format_numbers(((double)diff_recv/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1),
	    pfring_format_numbers(((double)diff_drop/(double)(delta_msec/1000)),  buf2, sizeof(buf2), 1));
  }
    
  fprintf(stderr, "\n=========================\n\n");

  last_tot_recv = tot_recv, last_tot_bytes = tot_bytes, last_tot_drop = tot_drop;
  last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(outzq);
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
  printf("zfifo - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A master thread reordering packets from multiple interfaces with\n"
         "hw timestamps support, and delivering them to a consumer thread. (experimental)\n\n");
  printf("-h              Print this help\n");
  printf("-i <devices>    Comma-separated list of devices\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-r <id>         Sorter thread core affinity\n");
  printf("-t <id>         Timer thread core affinity\n");
  printf("-g <id>         Consumer thread core affinity\n");
  printf("-a              Active packet wait\n");
  exit(-1);
}

/* *************************************** */

void* consumer_thread(void *user) {
  pfring_zc_pkt_buff *b = buffer;

  bind2core(bind_consumer_core);

  while(!do_shutdown) {

    if(pfring_zc_recv_pkt(outzq, &b, wait_for_packet) > 0) {

#if 0
      int i;

      for(i = 0; i < b->len; i++)
        printf("%02X ", pfring_zc_pkt_buff_data(b, outzq)[i]);
      printf("\n");
#endif

      consumers_stats.tot_recv++;
      consumers_stats.tot_bytes += b->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
    }

  }

  pfring_zc_sync_queue(outzq, rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *dev, c;
  long i;
  int cluster_id = -1;
  pthread_t thread;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:r:t:")) != '?') {
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
      bind_consumer_core = atoi(optarg);
      break;
    case 'r':
      bind_worker_core = atoi(optarg);
      break;
    case 't':
      bind_timer_core = atoi(optarg);
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();

  dev = strtok(device, ",");
  while(dev != NULL) {
    devices = realloc(devices, sizeof(char *) * (num_devices+1));
    devices[num_devices] = strdup(dev);
    num_devices++;
    dev = strtok(NULL, ",");
  }

  if (num_devices < 2) printHelp();

  zc = pfring_zc_create_cluster(
    cluster_id, 
    max_packet_len(devices[0]),
    0,
    (num_devices * (MAX_CARD_SLOTS + PREFETCH_BUFFERS)) + QUEUE_LEN + 1,
    numa_node_of_cpu(bind_worker_core), 
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  inzq = calloc(num_devices,     sizeof(pfring_zc_queue *));

  buffer = pfring_zc_get_packet_handle(zc);

  if (buffer == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle error\n");
    return -1;
  }

  for (i = 0; i < num_devices; i++) {
    inzq[i] = pfring_zc_open_device(zc, devices[i], rx_only, 0);

    if(inzq[0] == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), devices[i]);
      return -1;
    }
  }

  outzq = pfring_zc_create_queue(zc, QUEUE_LEN);

  if(outzq == NULL) {
    fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
    return -1;
  }

  wsp = pfring_zc_create_buffer_pool(zc, num_devices * PREFETCH_BUFFERS);

  if (wsp == NULL) {
    fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
    return -1;
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  printf("Starting sorter and consumer thread..\n");

  zw = pfring_zc_run_fifo(
    inzq, 
    outzq, 
    num_devices, 
    wsp,
    NULL /* idle callback */,
    !wait_for_packet, 
    bind_worker_core,
    bind_timer_core
  );

  if(zw == NULL) {
    fprintf(stderr, "pfring_zc_run_fifo error [%s]\n", strerror(errno));
    return -1;
  }

  pthread_create(&thread, NULL, consumer_thread, (void *) i);
  
  pthread_join(thread, NULL);

  pfring_zc_kill_worker(zw);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

