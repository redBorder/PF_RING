/*
 *
 * (C) 2014 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_SYSDIG_H_
#define _PFRING_MOD_SYSDIG_H_

#define RING_BUF_SIZE             1024 * 1024
#define SYSDIG_RING_LEN           RING_BUF_SIZE * 2
#define MIN_SYSDIG_DATA_AVAIL     100000          
#define BUFFER_EMPTY_WAIT_TIME_MS 30

#define MAX_NUM_SYSDIG_DEVICES    64

struct sysdig_ring_info {
  volatile u_int32_t head;
  volatile u_int32_t tail;
  volatile u_int64_t n_evts;		 /* Total number of events that were received by the driver. */
  volatile u_int64_t n_drops_buffer;	 /* Number of dropped events (buffer full). */
  volatile u_int64_t n_drops_pf;	 /* Number of dropped events (page faults). */
  volatile u_int64_t n_preemptions;	 /* Number of preemptions. */
  volatile u_int64_t n_context_switches; /* Number of received context switch events. */
};

typedef struct {
  int		          fd;
  char                    *ring_mmap;
  struct sysdig_ring_info *ring_info;  

  u_int32_t               last_evt_read_len;
} pfring_sysdig_device;

typedef struct {
  u_int8_t                num_devices;
  pfring_sysdig_device    devices[MAX_NUM_SYSDIG_DEVICES];
} pfring_sysdig;

#pragma pack(push, 1)
struct sysdig_event_header {
  u_int64_t ts;         /* timestamp, in nanoseconds from epoch */
  u_int64_t thread_id;  /* the thread that generated this event */
  u_int32_t event_len;  /* the event len, including the header */
  u_int16_t event_type; /* the event type */
};
#pragma pack(pop)


int  pfring_mod_sysdig_open (pfring *ring);
void pfring_mod_sysdig_close(pfring *ring);
int  pfring_mod_sysdig_stats(pfring *ring, pfring_stat *stats);
int  pfring_mod_sysdig_recv (pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_mod_sysdig_poll(pfring *ring, u_int wait_duration);
int  pfring_mod_sysdig_enable_ring(pfring *ring);
int  pfring_mod_sysdig_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_mod_sysdig_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_mod_sysdig_stats(pfring *ring, pfring_stat *stats);

#endif /* _PFRING_MOD_SYSDIG_H_ */
