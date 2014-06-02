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
#define PREFETCH_BUFFERS        8
#define QUEUE_LEN            8192
#define POOL_SIZE              16
#define CACHE_LINE_LEN         64

pfring_zc_cluster *zc;
pfring_zc_worker *zw;
pfring_zc_queue **inzqs;
pfring_zc_queue **outzqs;
pfring_zc_multi_queue *outzmq; /* fanout */
pfring_zc_buffer_pool **pools;
pfring_zc_buffer_pool *wsp;

u_int32_t num_devices = 0;
u_int32_t num_slaves = 1;
char **devices = NULL;

int bind_worker_core = -1;
int bind_time_pulse_core = -1;

volatile u_int64_t *pulse_timestamp_ns;

static struct timeval start_time;
u_int8_t wait_for_packet = 1, enable_vm_support = 0, time_pulse = 0;
volatile u_int8_t do_shutdown = 0;

/* ******************************** */

#define SET_TS_FROM_PULSE(p, t) { u_int64_t __pts = t; p->ts.tv_sec = __pts >> 32; p->ts.tv_nsec = __pts & 0xffffffff; }

void *time_pulse_thread(void *data) {
  u_int64_t ns;
  struct timespec tn;
#if 1
  u_int64_t pulse_clone = 0;
#endif

  bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    /* clock_gettime takes up to 30 nsec to get the time */
    clock_gettime(CLOCK_REALTIME, &tn);

    ns = ((u_int64_t) ((u_int64_t) tn.tv_sec * 1000000000) + (tn.tv_nsec));

#if 1 /* reduce cache thrashing*/ 
    if(ns >= pulse_clone + 100 /* nsec precision (avoid updating each cycle) */ ) {
#endif
      *pulse_timestamp_ns = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | tn.tv_nsec);
#if 1
      pulse_clone = ns;
    }
#endif
  }

  return NULL;
}

/* ******************************** */

void print_stats() {
  static u_int8_t print_all = 0;
  static struct timeval last_time;
  static unsigned long long last_tot_recv = 0, last_tot_slave_recv = 0;
  static unsigned long long last_tot_drop = 0, last_tot_slave_drop = 0;
  unsigned long long tot_recv = 0, tot_drop = 0, tot_slave_recv = 0, tot_slave_drop = 0;
  struct timeval end_time;
  char buf1[64], buf2[64], buf3[64], buf4[64];
  pfring_zc_stat stats;
  int i;

  if(start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  else
    print_all = 1;

  gettimeofday(&end_time, NULL);

  for (i = 0; i < num_devices; i++)
    if (pfring_zc_stats(inzqs[i], &stats) == 0)
      tot_recv += stats.recv, tot_drop += stats.drop;

  for (i = 0; i < num_slaves; i++)
    if (pfring_zc_stats(outzqs[i], &stats) == 0)
      tot_slave_recv += stats.recv, tot_slave_drop += stats.drop;

  fprintf(stderr, "=========================\n"
          "Absolute Stats: Recv %s pkts (%s drops) - Forwarded %s pkts (%s drops)\n", 
	  pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)tot_drop, buf2, sizeof(buf2), 0),
	  pfring_format_numbers((double)tot_slave_recv, buf3, sizeof(buf3), 0),
	  pfring_format_numbers((double)tot_slave_drop, buf4, sizeof(buf4), 0)
  );

  if(print_all && last_time.tv_sec > 0) {
    double delta_msec = delta_time(&end_time, &last_time);
    unsigned long long diff_recv = tot_recv - last_tot_recv;
    unsigned long long diff_drop = tot_drop - last_tot_drop;
    unsigned long long diff_slave_recv = tot_slave_recv - last_tot_slave_recv;
    unsigned long long diff_slave_drop = tot_slave_drop - last_tot_slave_drop;

    fprintf(stderr, "Actual Stats: Recv %s pps (%s drops) - Forwarded %s pps (%s drops)\n",
	    pfring_format_numbers(((double)diff_recv/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1),
	    pfring_format_numbers(((double)diff_drop/(double)(delta_msec/1000)),  buf2, sizeof(buf2), 1),
	    pfring_format_numbers(((double)diff_slave_recv/(double)(delta_msec/1000)),  buf3, sizeof(buf3), 1),
	    pfring_format_numbers(((double)diff_slave_drop/(double)(delta_msec/1000)),  buf4, sizeof(buf4), 1)
    );
  }
   
  fprintf(stderr, "=========================\n\n");
 
  last_tot_recv = tot_recv, last_tot_slave_recv = tot_slave_recv;
  last_tot_drop = tot_drop, last_tot_slave_drop = tot_slave_drop;
  last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  pfring_zc_kill_worker(zw);

  do_shutdown = 1;

  print_stats();
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
  printf("zbalance_ipc - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());

  printf("A master process balancing packets to multiple consumer processes (e.g. zcount_ipc -c <cluster id> -i <consumer id>).\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device (comma-separated list)\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-n <num_slaves> Number of slaves applications\n");
  printf("-m <hash mode>  Hashing modes:\n"
         "                0 - No hash: Round-Robin (default)\n"
         "                1 - IP hash\n"
         "                2 - Fan-out\n"
         "                3 - Fan-out (1st) + Round-Robin (2nd, 3rd, ..)\n");
  printf("-S <core id>    Enable Time Pulse thread and bind it to a core\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  printf("-l <sock list>  Enable VM support (comma-separated list of QEMU monitor sockets)\n");
  exit(-1);
}

/* *************************************** */

int32_t ip_distribution_func(pfring_zc_pkt_buff *pkt_handle, pfring_zc_queue *in_queue, void *user) {
  long num_out_queues = (long) user;
  if (time_pulse) SET_TS_FROM_PULSE(pkt_handle, *pulse_timestamp_ns);
  return pfring_zc_builtin_ip_hash(pkt_handle, in_queue) % num_out_queues;
}

/* *************************************** */

static int rr = -1;

int32_t rr_distribution_func(pfring_zc_pkt_buff *pkt_handle, pfring_zc_queue *in_queue, void *user) {
  long num_out_queues = (long) user;
  if (time_pulse) SET_TS_FROM_PULSE(pkt_handle, *pulse_timestamp_ns);
  if (++rr == num_out_queues) rr = 0;
  return rr;
}

/* *************************************** */

int32_t fo_distribution_func(pfring_zc_pkt_buff *pkt_handle, pfring_zc_queue *in_queue, void *user) {
  if (time_pulse) SET_TS_FROM_PULSE(pkt_handle, *pulse_timestamp_ns);
  return 0xffffffff; 
}

/* *************************************** */


int32_t fo_rr_distribution_func(pfring_zc_pkt_buff *pkt_handle, pfring_zc_queue *in_queue, void *user) {
  long num_out_queues = (long) user;
  if (time_pulse) SET_TS_FROM_PULSE(pkt_handle, *pulse_timestamp_ns);
  if (++rr == (num_out_queues - 1)) rr = 0;
  return (1 << 0 /* full traffic on 1st slave */ ) | (1 << (1 + rr) /* round-robin on other slaves */ );
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char *device = NULL, *dev; 
  char *vm_sockets = NULL, *vm_sock; 
  long i;
  int cluster_id = -1;
  int hash_mode = 0;
  pthread_t time_thread;
  int rc;

  start_time.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:m:n:l:S:")) != '?') {
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
    case 'n':
      num_slaves = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'g':
      bind_worker_core = atoi(optarg);
      break;
    case 'l':
      enable_vm_support = 1;
      vm_sockets = strdup(optarg);
      break;
    case 'S':
      time_pulse = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();
  if (num_slaves < 1) printHelp();

  dev = strtok(device, ",");
  while(dev != NULL) {
    devices = realloc(devices, sizeof(char *) * (num_devices+1));
    devices[num_devices] = strdup(dev);
    num_devices++;
    dev = strtok(NULL, ",");
  }

  zc = pfring_zc_create_cluster(
    cluster_id, 
    max_packet_len(devices[0]),
    0,
    (num_devices * MAX_CARD_SLOTS) + (num_slaves * (QUEUE_LEN + POOL_SIZE)) + PREFETCH_BUFFERS, 
    numa_node_of_cpu(bind_worker_core),
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  inzqs  = calloc(num_devices, sizeof(pfring_zc_queue *));
  outzqs = calloc(num_slaves,  sizeof(pfring_zc_queue *));
  pools  = calloc(num_slaves,  sizeof(pfring_zc_buffer_pool *));

  for (i = 0; i < num_devices; i++) {
    inzqs[i] = pfring_zc_open_device(zc, devices[i], rx_only, 0);

    if(inzqs[0] == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), devices[i]);
      return -1;
    }
  }

  for (i = 0; i < num_slaves; i++) { 
    outzqs[i] = pfring_zc_create_queue(zc, QUEUE_LEN);

    if(outzqs[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
      return -1;
    }
  }

  for (i = 0; i < num_slaves; i++) { 
    pools[i] = pfring_zc_create_buffer_pool(zc, POOL_SIZE);

    if (pools[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
      return -1;
    }
  }

  wsp = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);

  if (wsp == NULL) {
    fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
    return -1;
  }

  if (enable_vm_support) {
    vm_sock = strtok(vm_sockets, ",");
    while(vm_sock != NULL) {

      rc = pfring_zc_vm_register(zc, vm_sock);

      if (rc < 0) {
        fprintf(stderr, "pfring_zc_vm_register(%s) error\n", vm_sock);
        return -1;
      }

      vm_sock = strtok(NULL, ",");
    }

    rc = pfring_zc_vm_backend_enable(zc);

    if (rc < 0) {
      fprintf(stderr, "pfring_zc_vm_backend_enable error\n");
      return -1;
    }
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  if (time_pulse) {
    pulse_timestamp_ns = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
    while (!*pulse_timestamp_ns && !do_shutdown); /* wait for ts */
  }

  printf("Starting balancer for %d slave applications..\n", num_slaves);

  if (hash_mode < 2) { /* balancer */

    zw = pfring_zc_run_balancer(
      inzqs, 
      outzqs, 
      num_devices, 
      num_slaves,
      wsp,
      round_robin_bursts_policy,
      NULL,
      hash_mode == 0 ? rr_distribution_func : (time_pulse ? ip_distribution_func : NULL /* built-in IP-based  */),
      (void *) ((long) num_slaves),
      !wait_for_packet, 
      bind_worker_core
    );

  } else { /* fanout */
    
    outzmq = pfring_zc_create_multi_queue(outzqs, num_slaves);

    if(outzmq == NULL) {
      fprintf(stderr, "pfring_zc_create_multi_queue error [%s]\n", strerror(errno));
      return -1;
    }

    zw = pfring_zc_run_fanout(
      inzqs, 
      outzmq, 
      num_devices,
      wsp,
      round_robin_bursts_policy, 
      NULL /* idle callback */,
      hash_mode == 3 ? fo_rr_distribution_func : (time_pulse ? fo_distribution_func : NULL /* built-in send-to-all */), 
      (void *) ((long) num_slaves),
      !wait_for_packet, 
      bind_worker_core
    );

  }

  if(zw == NULL) {
    fprintf(stderr, "pfring_zc_run_balancer error [%s]\n", strerror(errno));
    return -1;
  }
  
  while (!do_shutdown) sleep(1);

  if (time_pulse)
    pthread_join(time_thread, NULL);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

