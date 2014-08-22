/*
 *
 * (C) 2014 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_mod_sysdig.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/* **************************************************** */

int pfring_mod_sysdig_open(pfring *ring) {
  u_int8_t device_id = 0;
  pfring_sysdig *sysdig = NULL;

  ring->close                    = pfring_mod_sysdig_close;
  ring->recv                     = pfring_mod_sysdig_recv;
  ring->poll                     = pfring_mod_sysdig_poll;
  ring->enable_ring              = pfring_mod_sysdig_enable_ring;
  ring->set_poll_watermark       = pfring_mod_sysdig_set_poll_watermark;
  ring->set_socket_mode          = pfring_mod_sysdig_set_socket_mode;
  ring->stats                    = pfring_mod_sysdig_stats;
  ring->get_bound_device_ifindex = pfring_mod_sysdig_get_bound_device_ifindex;
  ring->priv_data = malloc(sizeof(pfring_sysdig));

  if(ring->priv_data == NULL)
    goto sysdig_ret_error;

  memset(ring->priv_data, 0, sizeof(pfring_sysdig));
  sysdig = (pfring_sysdig*)ring->priv_data;
 
  sysdig->num_devices = sysconf(_SC_NPROCESSORS_ONLN); /* # devices = # CPUs */
  
  if(sysdig->num_devices > MAX_NUM_SYSDIG_DEVICES) {
    fprintf(stderr, "Internal error: too many devices %u\n", sysdig->num_devices);
    return(-1);
  }

  sysdig->bytes_watermark = DEFAULT_SYSDIG_DATA_AVAIL;
  if(ring->caplen > MAX_CAPLEN) ring->caplen = MAX_CAPLEN;
  ring->poll_duration = DEFAULT_POLL_DURATION;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    char device_name[48];

    snprintf(device_name, sizeof(device_name), "/dev/sysdig%u", device_id);

    if((sysdig->devices[device_id].fd = open((char *)device_name, O_RDWR | O_SYNC)) < 0) {
      fprintf(stderr, "Error opening %s\n", device_name);
      goto sysdig_open_error;
    }

    if((sysdig->devices[device_id].ring_mmap = 
	(char*)mmap(0, SYSDIG_RING_LEN,
		    PROT_READ, MAP_SHARED,
		    sysdig->devices[device_id].fd, 0)) == MAP_FAILED) {
      fprintf(stderr, "Unable to mmap ring for %s\n", device_name);
      goto sysdig_open_error;
    }

    sysdig->devices[device_id].ring_info = 
      (struct sysdig_ring_info*)mmap(0, sizeof(struct sysdig_ring_info),
				     PROT_READ | PROT_WRITE,
				     MAP_SHARED,
				     sysdig->devices[device_id].fd, 0);
    if(sysdig->devices[device_id].ring_info == MAP_FAILED) {
      fprintf(stderr, "Unable to mmap info ring for %s\n", device_name);
      goto sysdig_open_error;
    }
  }
  return 0; /* Everything looks good so far */

 sysdig_open_error:
  pfring_mod_sysdig_close(ring);

 sysdig_ret_error:
  return -1;
}

/* **************************************************** */

void pfring_mod_sysdig_close(pfring *ring) {
  pfring_sysdig *sysdig;
  u_int8_t device_id = 0;

  if(ring->priv_data == NULL)
    return;

  sysdig = (pfring_sysdig *)ring->priv_data;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    if(sysdig->devices[device_id].ring_info)
      munmap(sysdig->devices[device_id].ring_info, sizeof(struct sysdig_ring_info));

    if(sysdig->devices[device_id].ring_mmap)
      munmap(sysdig->devices[device_id].ring_mmap, SYSDIG_RING_LEN);

    if(sysdig->devices[device_id].fd)
      close(sysdig->devices[device_id].fd);
  }
}

/* **************************************************** */

static u_int32_t pfring_sysdig_get_data_available(pfring_sysdig_device *dev) {
  u_int32_t rc, head = dev->ring_info->head, tail = dev->ring_info->tail;
  
  if(tail > head) /* Ring wrap */
    rc = RING_BUF_SIZE - tail + head;
  else
    rc = head - tail;

  // printf("%s() : %u\n", __FUNCTION__, rc);
  return(rc);
}

/* **************************************************** */

static void sysdig_get_first_event(pfring_sysdig *sysdig,
				   pfring_sysdig_device *dev, 
				  struct sysdig_event_header **ev) {
  u_int32_t next_tail = dev->ring_info->tail + dev->last_evt_read_len;

  /* Check if we have a packet already read but not taken into account */
  if(dev->last_evt_read_len > 0) {
    if(next_tail >= RING_BUF_SIZE)
      next_tail = next_tail - RING_BUF_SIZE; /* Start over (ring wrap) */

    /* Event consumed: update tail */
    dev->ring_info->tail = next_tail;
  }

  if(pfring_sysdig_get_data_available(dev) < sysdig->bytes_watermark /* Too little data */)
    *ev = NULL, dev->last_evt_read_len = 0;
  else {
    // printf("%u ", dev->ring_info->tail);
    *ev = (struct sysdig_event_header*)(dev->ring_mmap + next_tail);
    dev->last_evt_read_len = (*ev)->event_len;

    // printf("%u(%u) ", dev->ring_info->tail, (*ev)->event_type);
  }
}

/* **************************************************** */

int pfring_mod_sysdig_recv(pfring *ring, u_char** buffer, u_int buffer_len, 
			   struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet) {

  u_int8_t device_id, ret_device_id = 0;
  pfring_sysdig *sysdig;
  struct sysdig_event_header *ret_event = NULL;

  if(ring->priv_data == NULL)
    return -1;

  sysdig = (pfring_sysdig *)ring->priv_data;

  if(ring->reentrant)
    pthread_rwlock_wrlock(&ring->rx_lock);

 check_and_poll:
  if(ring->break_recv_loop)
    goto exit; /* retval = 0 */

  __sync_synchronize();

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    struct sysdig_event_header *this_event;

    sysdig_get_first_event(sysdig, &sysdig->devices[device_id], &this_event);

    if(this_event) {
      if(ret_event == NULL)
	ret_event = this_event, ret_device_id = device_id;
      else {
	if(this_event->ts < ret_event->ts) {
	  /* This event is older than the previous one hence I need
	     to push pack the ret_event */
	  
	  sysdig->devices[ret_device_id].last_evt_read_len = 0;
	  ret_event = this_event, ret_device_id = device_id;
	} else {
	  sysdig->devices[device_id].last_evt_read_len = 0; /* Ignore this event */
	}
      }
    }
  }

  if(ret_event == NULL) {
    /* No event returned */

    if(wait_for_incoming_packet) {
      usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
      goto check_and_poll;
    }
  } else {
    if(buffer_len > 0) {
      /* one copy */
      u_int len = ret_event->event_len;
      
      if(len > ring->caplen) len = ring->caplen;
      if(len > buffer_len)   len = buffer_len;

      memcpy(*buffer, ret_event, len);
      hdr->caplen = len, hdr->len = ret_event->event_len;
    } else {
      /* zero copy */
      *buffer = (u_char*)ret_event;
      hdr->caplen = hdr->len = ret_event->event_len;
    }

    hdr->extended_hdr.timestamp_ns = ret_event->ts;
    hdr->extended_hdr.pkt_hash = hdr->extended_hdr.if_index = ret_device_id; /* CPU id */

    /*
      The two statements below are kinda a waste of time as timestamp_ns
      is more than enough 
    */
    hdr->ts.tv_sec  = hdr->extended_hdr.timestamp_ns / 1000000000,
      hdr->ts.tv_usec = (hdr->extended_hdr.timestamp_ns / 1000) % 1000000;
  }

 exit:
  if(ring->reentrant)
    pthread_rwlock_unlock(&ring->rx_lock);
  
  return(ret_event ? 1 : 0);
}

/* **************************************************** */

int pfring_mod_sysdig_enable_ring(pfring *ring) {
  u_int32_t device_id;
  pfring_sysdig *sysdig;

  if(ring->priv_data == NULL)
    return -1;

  sysdig = (pfring_sysdig *)ring->priv_data;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    if(ioctl(sysdig->devices[device_id].fd, PPM_IOCTL_ENABLE_CAPTURE)) {
      return(-1);
    }
  }

  return 0;
}

/* **************************************************** */

int pfring_mod_sysdig_poll(pfring *ring, u_int wait_duration) {
  pfring_sysdig *sysdig;
  u_int8_t device_id;

  if(ring->priv_data == NULL)
    return -1;

  sysdig = (pfring_sysdig *)ring->priv_data;

  while(1) {
    for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
      if(pfring_sysdig_get_data_available(&sysdig->devices[device_id]) >= sysdig->bytes_watermark)
	return(1);
    }
    
    /* No data found */
    if(wait_duration == 0) return(0);
    
    usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
    wait_duration--;
  }

  return(1); /* Not reached */
}

/* ******************************* */

int pfring_mod_sysdig_set_socket_mode(pfring *ring, socket_mode mode) {
  return((mode == recv_only_mode) ? 0 : -1);
}

/* ******************************* */

int pfring_mod_sysdig_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  pfring_sysdig *sysdig = NULL;

  if(ring->priv_data == NULL)    
    return(-1);

  sysdig = (pfring_sysdig*)ring->priv_data;
  sysdig->bytes_watermark = watermark * 8192;

  return(0);
}

/* ******************************* */

int pfring_mod_sysdig_stats(pfring *ring, pfring_stat *stats) {
  u_int8_t device_id;
  pfring_sysdig *sysdig = NULL;

  if(ring->priv_data == NULL)    
    return(-1);
  else    
    sysdig = (pfring_sysdig*)ring->priv_data;

  stats->recv = 0, stats->drop = 0;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    stats->recv += sysdig->devices[device_id].ring_info->n_evts,
      stats->drop += 
      sysdig->devices[device_id].ring_info->n_drops_buffer +
      sysdig->devices[device_id].ring_info->n_drops_pf;            
  }

  return(0);
}

/* **************************************************** */

int pfring_mod_sysdig_get_bound_device_ifindex(pfring *ring, int *if_index) {
  *if_index = 0; /* Dummy index */

  return(0);
}


