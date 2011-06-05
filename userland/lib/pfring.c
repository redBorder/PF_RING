/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 * This code includes contributions courtesy of
 * - Fedor Sakharov <fedor.sakharov@gmail.com>
 *
 */

#define __USE_XOPEN2K
#include <sys/types.h>
#include <pthread.h>

#include "pfring.h"

// #define RING_DEBUG

/* ********************************* */

#include "pfring_mod.h"

#ifdef HAVE_DAG
#include "pfring_dag.h"
#endif

#ifdef HAVE_DNA
#include "pfring_mod_dna.h"
#endif

static pfring_module_info pfring_module_list[] = {
#ifdef HAVE_DAG
  {
    .name = "dag",
    .open = pfring_dag_open,
  },
#endif
#ifdef HAVE_DNA
  {
    .name = "dna",
    .open = pfring_dna_open,
  },
#endif
#ifdef HAVE_VIRTUAL
  {
    .name = "host",
    .open = pfring_v_open,
  },
#endif
  {0}
};

/* ******************************* */

void pfring_config(u_short cpu_percentage) {
  static u_int pfring_initialized = 0;

  if(!pfring_initialized) {
    struct sched_param schedparam;

    /*if(cpu_percentage >= 50) mlockall(MCL_CURRENT|MCL_FUTURE); */

    pfring_initialized = 1;
    schedparam.sched_priority = cpu_percentage;
    if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
      printf("error while setting the scheduler, errno=%i\n", errno);
      exit(1);
    }
  }
}

/* ******************************* */

int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  if (ring && ring->add_hw_rule)
    return ring->add_hw_rule(ring, rule);

  return -1;
}

/* ******************************* */

int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  if (ring && ring->remove_hw_rule)
    return ring->remove_hw_rule(ring, rule_id);

  return -1;
}

/* ******************************* */

int pfring_set_channel_id(pfring *ring, u_int32_t channel_id) {
  if (ring && ring->set_channel_id)
    return ring->set_channel_id(ring, channel_id);

  return -1;
}

/* ******************************* */

int pfring_set_application_name(pfring *ring, char *name) {
  if (ring && ring->set_application_name)
    return ring->set_application_name(ring, name);

  return -1;
}

/* **************************************************** */

int pfring_bind(pfring *ring, char *device_name) { 
  if (ring && ring->bind)
    return ring->bind(ring, device_name);

  return -1;
}

/* **************************************************** */

pfring* pfring_open(char *device_name, u_int8_t promisc,
		    u_int32_t caplen, u_int8_t _reentrant) {
  int i = -1;
  int mod_found = 0;
  int ret;
  char *str;

  pfring *ring = (pfring*)malloc(sizeof(pfring));

  if(ring == NULL)
    return NULL;
  
  memset(ring, 0, sizeof(pfring));

  ring->promisc     = promisc;
  ring->caplen      = caplen;
  ring->reentrant   = _reentrant;

#ifdef RING_DEBUG
  printf("pfring_open: device_name=%s\n", device_name);
#endif
  /* modules */

  if(device_name)
    while (pfring_module_list[++i].name){
      if (!(str = strstr(device_name, pfring_module_list[i].name))) continue;
      if (!(str = strchr(str, ':')))                                continue;
      if (!pfring_module_list[i].open)                              continue;

#ifdef RING_DEBUG
      printf("pfring_open: found module %s\n", pfring_module_list[i].name);
#endif

      mod_found = 1;
      ring->device_name = strdup(++str);
      ret = pfring_module_list[i].open(ring);
      break;
    }

  /* default */
  if (!mod_found) {
    ring->device_name = strdup(device_name ? device_name : "any");

    ret = pfring_mod_open(ring);
  }

  if (ret < 0){
    free(ring->device_name);
    free(ring);
    return NULL;
  }

  if(ring->reentrant)
    pthread_spin_init(&ring->spinlock, PTHREAD_PROCESS_PRIVATE);

  ring->initialized = 1;

  return ring;
}

/* **************************************************** */

void pfring_shutdown(pfring *ring) {
  if (!ring)
    return;

  ring->is_shutting_down = ring->break_recv_loop = 1;
}

/* **************************************************** */

void pfring_close(pfring *ring) {
  if (!ring)
    return;

  pfring_shutdown(ring);

  if (ring->close)
    ring->close(ring);
 
  if(ring->reentrant)
    pthread_spin_destroy(&ring->spinlock);

  free(ring->device_name);
  free(ring);
}

/* **************************************************** */

int pfring_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  if (ring && ring->send)
    return ring->send(ring, pkt, pkt_len, flush_packet);

  return -1;
}

/* **************************************************** */

int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  if (ring && ring->set_poll_watermark)
    return ring->set_poll_watermark(ring, watermark);

  return(-1);
}

/* **************************************************** */

int pfring_set_poll_duration(pfring *ring, u_int duration) {
  if (ring && ring->set_poll_duration)
    return ring->set_poll_duration(ring, duration);

  return -1;
}

/* **************************************************** */

u_int8_t pfring_get_num_rx_channels(pfring *ring) {
  if (ring && ring->get_num_rx_channels)
    return ring->get_num_rx_channels(ring);

  return 1;
}

/* **************************************************** */

int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  if (ring && ring->set_sampling_rate)
    return ring->set_sampling_rate(ring, rate);

  return(-1);
}

/* ******************************* */

int pfring_stats(pfring *ring, pfring_stat *stats) {
  if (ring && ring->stats)
    return ring->stats(ring, stats);

  return -1;
}

/* **************************************************** */

int pfring_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		struct pfring_pkthdr *hdr,
		u_int8_t wait_for_incoming_packet) {
  if (ring && ring->recv)
    return ring->recv(ring, buffer, buffer_len, hdr, wait_for_incoming_packet);

  return -1;
}

/* **************************************************** */

int pfring_loop(pfring *ring, pfringProcesssPacket looper, const u_char *user_bytes) {
  u_char *buffer = NULL;
  struct pfring_pkthdr hdr;
  int rc = 0;

  if (!ring)
    return -1;

  ring->break_recv_loop = 0;

  while(!ring->break_recv_loop) {
    rc = pfring_recv(ring, &buffer, 0, &hdr, 1);
    if(rc < 0)
      break;
    else if(rc > 0)
      looper(&hdr, buffer, user_bytes);
  }

  return(rc);
}

/* **************************************************** */

void pfring_breakloop(pfring *ring) {
  if (ring)
    ring->break_recv_loop = 1;
}

/* **************************************************** */

int pfring_get_selectable_fd(pfring *ring) {
  if (ring && ring->get_selectable_fd)
    return ring->get_selectable_fd(ring);

  return -1;
}

