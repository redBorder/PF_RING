/*
** Copyright (C) 2010-12 ntop.org
**
** Authors: Luca Deri <deri@ntop.org>
**          Alfredo Cardigliano <cardigliano@ntop.org>
**
** Copyright(C) 2010 Sourcefire, Inc.
** Author: Michael R. Altizer <maltizer@sourcefire.com>
**         Will Metcalf <william.metcalf@gmail.com>
**
** Contributors: Tim Covel <tcovel@metaflows.com>
**		 Hong Zhu <hongzhu.ca@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysinfo.h> /* get_nprocs(void) */

#include "pfring.h"
#include "sfbpf.h"
#include "daq_api.h"

#define DAQ_PF_RING_VERSION 1

typedef struct _pfring_context
{
  char *device, *twin_device;
  char *filter_string;
  int snaplen;
  pfring *ring_handle, *twin_ring_handle;
  char errbuf[1024];
  u_char *pkt_buffer;
  u_int breakloop;
  int promisc_flag;
  int timeout;
  u_int16_t filter_count;
  DAQ_Analysis_Func_t analysis_func;
  uint32_t netmask;
  DAQ_Stats_t stats;
  u_int clusterid;
  u_int8_t use_kernel_filters;
  u_int bindcpu;
  uint32_t base_recv[2];
  uint32_t base_drop[2];
  DAQ_State state;
} Pfring_Context_t;

static void pfring_daq_reset_stats(void *handle);
static int pfring_daq_set_filter(void *handle, const char *filter);

static pfring* pfring_daq_open(Pfring_Context_t *context, char *device, int td) {
  uint32_t default_net = 0xFFFFFF00;
  int pfring_rc;
  pfring *ring_handle;

  if(!device) {
    DPE(context->errbuf, "%s", "PF_RING a device must be specified");
    return NULL;
  }

  if(device) {
    int flags = PF_RING_PROMISC /* PF_RING_REENTRANT */;

    context->pkt_buffer = NULL;

    if(context->promisc_flag) flags |= PF_RING_PROMISC;

    ring_handle = pfring_open(device, context->snaplen, flags);

    if(!ring_handle) {
      DPE(context->errbuf, "pfring_open(): unable to open device '%s'. Please use -i <device>", device);
      return NULL;
    }
  }

  if (context->twin_device == NULL) { /* passive mode */
    /* default direction: rx_and_tx_direction */
    pfring_set_socket_mode(ring_handle, recv_only_mode);
  } else { /* inline mode */
    pfring_set_direction(ring_handle, rx_only_direction);
    /* default mode: recv_and_send_mode */
  }

  if(context->clusterid > 0) {
    pfring_rc = pfring_set_cluster(ring_handle, context->clusterid, cluster_per_flow_2_tuple);

    if(pfring_rc != 0) {
      DPE(context->errbuf, "pfring_set_cluster returned %d", pfring_rc);
      return NULL;
    }
  }

  context->netmask = htonl(default_net);
 
  return(ring_handle);
}

static int update_hw_stats(Pfring_Context_t *context) {
  pfring_stat ps;

  if(context->ring_handle && context->device) {
    memset(&ps, 0, sizeof(pfring_stat));
    if(pfring_stats(context->ring_handle, &ps) == -1) {
      DPE(context->errbuf, "%s", "pfring_stats error");
      return DAQ_ERROR;
    }

    context->stats.hw_packets_received = ps.recv - context->base_recv[0];
    context->stats.hw_packets_dropped = ps.drop - context->base_drop[0];
  }

  if(context->twin_ring_handle && context->twin_device) {
    memset(&ps, 0, sizeof(pfring_stat));
    if(pfring_stats(context->twin_ring_handle, &ps) == -1) {
      DPE(context->errbuf, "%s", "pfring_stats error");
      return DAQ_ERROR;
    }

    context->stats.hw_packets_received += ps.recv - context->base_recv[1];
    context->stats.hw_packets_dropped  += ps.drop - context->base_drop[1];
  }

  return DAQ_SUCCESS;
}

static int pfring_daq_initialize(const DAQ_Config_t *config,
				 void **ctxt_ptr, char *errbuf, size_t len) {
  Pfring_Context_t *context;
  DAQ_Dict* entry;
  /* taken from pfcount example */
  u_int numCPU = get_nprocs();

  context = calloc(1, sizeof(Pfring_Context_t));
  if(!context) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
    return DAQ_ERROR_NOMEM;
  }

  context->clusterid = 0;
  context->snaplen = config->snaplen;
  context->promisc_flag =(config->flags & DAQ_CFG_PROMISC);
  context->timeout =(config->timeout > 0) ?(int) config->timeout : -1;
  context->filter_count = 0;
  context->use_kernel_filters = 1;

  context->device = strdup(config->name);
  if(!context->device) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
    free(context);
    return DAQ_ERROR_NOMEM;
  }

  if(config->mode == DAQ_MODE_READ_FILE) {
    snprintf(errbuf, len, "%s: function not supported on PF_RING", __FUNCTION__);
    free(context);

    return DAQ_ERROR;
  } else if(config->mode == DAQ_MODE_INLINE) {
    /* ethX:ethY */
    char *column = strchr(context->device, ':');

    if(column != NULL) {
      column[0] = '\0';
      context->twin_device = &column[1];
    }
  }

  for(entry = config->values; entry; entry = entry->next) {
    if(!entry->value || !*entry->value) {
      snprintf(errbuf, len,
	       "%s: variable needs value(%s)\n", __FUNCTION__, entry->key);
      return DAQ_ERROR;
    } else if(!strcmp(entry->key, "clusterid")) {
      char* end = entry->value;
      context->clusterid =(int)strtol(entry->value, &end, 0);
      if(*end
	 || (context->clusterid <= 0)
	 || (context->clusterid > 65535)) {
	snprintf(errbuf, len, "%s: bad clusterid(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key, "no-kernel-filters")) {
      context->use_kernel_filters = 0;
    } else if(!strcmp(entry->key, "bindcpu")) {
      char* end = entry->value;
      context->bindcpu =(int)strtol(entry->value, &end, 0);
      if(*end
	 || (context->bindcpu >= numCPU)) {
	snprintf(errbuf, len, "%s: bad bindcpu(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      } else {
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET((int)context->bindcpu, &mask);
	if(sched_setaffinity(0, sizeof(mask), &mask) < 0) {
	  snprintf(errbuf, len, "%s:failed to set bindcpu(%u) on pid %i\n",
		   __FUNCTION__, context->bindcpu, getpid());
	  return DAQ_ERROR;
	}
      }
    } else {
      snprintf(errbuf, len,
	       "%s: unsupported variable(%s=%s)\n",
	       __FUNCTION__, entry->key, entry->value);
      return DAQ_ERROR;
    }
  }

  context->state = DAQ_STATE_INITIALIZED;

  *ctxt_ptr = context;
  return DAQ_SUCCESS;
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret;
  struct sfbpf_program fcode;

  if(context->ring_handle) {
    if(sfbpf_compile(context->snaplen, DLT_EN10MB, &fcode,
		     filter, 0 /* 1: optimize */, htonl(context->netmask)) < 0) {
      DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
      return DAQ_ERROR;
    }

    if(setsockopt(pfring_get_selectable_fd(context->ring_handle), 0,
		  SO_ATTACH_FILTER, &fcode, sizeof(fcode)) == 0) {
      ret = DAQ_SUCCESS;

      if(context->twin_device) {  
	if(setsockopt(pfring_get_selectable_fd(context->twin_ring_handle), 0,
		      SO_ATTACH_FILTER, &fcode, sizeof(fcode)) == 0) {
          ret = DAQ_SUCCESS;

        } else ret = DAQ_ERROR; 
      }
    } else ret = DAQ_ERROR;

    sfbpf_freecode(&fcode);
  } else {
    /* Just check if the filter is valid */
    if(sfbpf_compile(context->snaplen, DLT_EN10MB, &fcode, 
    		     filter, 0 /* 1: optimize */, 0 /* netmask */) < 0) {
      DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
      return DAQ_ERROR;
    }

    ret = DAQ_SUCCESS;

    if(context->filter_string)
      free(context->filter_string);

    context->filter_string = strdup(filter);

    if(!context->filter_string) {
      DPE(context->errbuf, "%s: Couldn't allocate memory for the filter string!",
	  __FUNCTION__);
      ret = DAQ_ERROR;
    }

    sfbpf_freecode(&fcode);
  }

  return ret;
}

static int pfring_daq_start(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(context->ring_handle == NULL) {
    context->ring_handle = pfring_daq_open(context, context->device, 0);

    if(context->ring_handle == NULL)
      return DAQ_ERROR;
  }

  if(context->twin_device) {
    context->twin_ring_handle = pfring_daq_open(context, context->twin_device, 1);

    if(context->twin_ring_handle == NULL)
      return DAQ_ERROR;
  }

  if(context->filter_string) {
    if(pfring_daq_set_filter(context, context->filter_string))
      return DAQ_ERROR;
  }

  pfring_daq_reset_stats(context);
  context->state = DAQ_STATE_STARTED;

  return DAQ_SUCCESS;
}

static int pfring_daq_send_packet(Pfring_Context_t *context, pfring *send_ring, u_int pkt_len)
{
  if(send_ring == NULL) return(DAQ_SUCCESS);

  if(pfring_send(send_ring,(char*)context->pkt_buffer,
		 pkt_len, 1 /* flush packet */) < 0) {
    DPE(context->errbuf, "%s", "pfring_send() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;

  return(DAQ_SUCCESS);
}

static int pfring_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, void *user) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  int ret;
  pfring *current_ring, *send_ring;

  context->analysis_func = callback;
  context->breakloop = 0;

  pfring_enable_ring(context->ring_handle);

  if(context->twin_ring_handle != NULL)
    pfring_enable_ring(context->twin_ring_handle);

  while((!context->breakloop) && ((cnt == -1) || (cnt > 0))) {
    struct pfring_pkthdr phdr;
    DAQ_PktHdr_t hdr;
    DAQ_Verdict verdict;

    memset(&phdr, 0, sizeof(phdr));

    ret = pfring_recv((current_ring = context->ring_handle),
		      &context->pkt_buffer, 0, &phdr, 0 /* Dont't wait */);

    if((ret <= 0) &&(context->twin_ring_handle != NULL))
      ret = pfring_recv((current_ring = context->twin_ring_handle),
			&context->pkt_buffer, 0, &phdr, 0 /* Dont't wait */);

    if(ret <= 0) {
      /* No packet to read: let's poll */
      struct pollfd pfd[2];
      int num = 1, rc;

      pfd[0].fd = context->ring_handle->fd, pfd[0].events = POLLIN, pfd[0].revents = 0;

      if(context->twin_ring_handle)
	pfd[1].fd = context->twin_ring_handle->fd, pfd[1].events = POLLIN, pfd[1].revents = 0, num = 2;

      rc = poll(pfd, num, context->timeout);

      if(rc < 0) {
	if(errno == EINTR)
	  break;

	DPE(context->errbuf, "%s: Poll failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
	return DAQ_ERROR;
      }
    } else {
      hash_filtering_rule hash_rule;

      hdr.caplen = phdr.caplen;
      hdr.pktlen = phdr.len;
      hdr.ts = phdr.ts;
      hdr.device_index = phdr.extended_hdr.if_index;
      hdr.flags = 0;

      context->stats.packets_received++;
      verdict = context->analysis_func(user, &hdr,(u_char*)context->pkt_buffer);
      if(verdict >= MAX_DAQ_VERDICT)
	verdict = DAQ_VERDICT_PASS;

      switch(verdict) {
      case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
      case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
      case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */

	if(context->use_kernel_filters) {
	  memset(&hash_rule, 0, sizeof(hash_rule));

	  pfring_parse_pkt(context->pkt_buffer, &phdr, 4, 0, 0);
	  /* or use pfring_recv_parsed() to force parsing. */

	  hash_rule.rule_id     = context->filter_count++;
	  hash_rule.vlan_id     = phdr.extended_hdr.parsed_pkt.vlan_id;
	  hash_rule.proto       = phdr.extended_hdr.parsed_pkt.l3_proto;
	  memcpy(&hash_rule.host_peer_a, &phdr.extended_hdr.parsed_pkt.ipv4_src, sizeof(ip_addr));
	  memcpy(&hash_rule.host_peer_b, &phdr.extended_hdr.parsed_pkt.ipv4_dst, sizeof(ip_addr));
	  hash_rule.port_peer_a = phdr.extended_hdr.parsed_pkt.l4_src_port;
	  hash_rule.port_peer_b = phdr.extended_hdr.parsed_pkt.l4_dst_port;
	  hash_rule.rule_action = (verdict == DAQ_VERDICT_BLACKLIST) ?
	    dont_forward_packet_and_stop_rule_evaluation : forward_packet_and_stop_rule_evaluation;
	  hash_rule.plugin_action.plugin_id = NO_PLUGIN_ID;

	  /* Purge rules idle (i.e. with no packet matching) for more than 1h */
	  pfring_purge_idle_hash_rules(context->ring_handle, 3600 /* 1h */);

	  pfring_handle_hash_filtering_rule(context->ring_handle, &hash_rule, 1 /* add_rule */);

	  /*	
		printf("[DEBUG] %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d Verdict=%d [pfring_handle_hash_filtering_rule=%d]\n", 
		hash_rule.host_peer_a.v4 >> 24 & 0xFF, hash_rule.host_peer_a.v4 >> 16 & 0xFF,
		hash_rule.host_peer_a.v4 >>  8 & 0xFF, hash_rule.host_peer_a.v4 >>  0 & 0xFF, 
		hash_rule.port_peer_a & 0xFFFF, 
		hash_rule.host_peer_b.v4 >> 24 & 0xFF, hash_rule.host_peer_b.v4 >> 16 & 0xFF,
		hash_rule.host_peer_b.v4 >>  8 & 0xFF, hash_rule.host_peer_b.v4 >>  0 & 0xFF,
		hash_rule.port_peer_b & 0xFFFF, 
		verdict, rc);
	  */

	}

	if(verdict == DAQ_VERDICT_BLACKLIST) {
	  break;
	} else {
	  /* No break here ! as we need to forward the packet */
	}

      case DAQ_VERDICT_PASS:    /* Pass the packet */
      case DAQ_VERDICT_REPLACE: /* Pass a packet that has been modified in-place.(No resizing allowed!) */
	send_ring = (current_ring == context->ring_handle) ? context->twin_ring_handle : context->ring_handle;
	pfring_daq_send_packet(context, send_ring, hdr.caplen);
	break;

      case DAQ_VERDICT_BLOCK:   /* Block the packet. */
	/* Nothing to do really */
	break;

      case MAX_DAQ_VERDICT:
	/* No way we can reach this point */
	break;
      }

      context->stats.verdicts[verdict]++;
      if(cnt > 0) cnt--;
    }
  }

  return 0;
}

static int pfring_daq_inject(void *handle, const DAQ_PktHdr_t *hdr,
			     const uint8_t *packet_data, uint32_t len, int reverse) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(pfring_send(context->ring_handle,
		 (char*)packet_data, len, 1 /* flush packet */) < 0) {
    DPE(context->errbuf, "%s", "pfring_send() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;
  return DAQ_SUCCESS;
}

static int pfring_daq_breakloop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context->ring_handle)
    return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(context->ring_handle) {
    /* Store the hardware stats for post-stop stat calls. */
    update_hw_stats(context);
    pfring_close(context->ring_handle);
    context->ring_handle = NULL;
  }

  context->state = DAQ_STATE_STOPPED;

  return DAQ_SUCCESS;
}

static void pfring_daq_shutdown(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(context->ring_handle)
    pfring_close(context->ring_handle);

  if(context->twin_ring_handle)
    pfring_close(context->twin_ring_handle);

  if(context->device)
    free(context->device);

  if(context->filter_string)
    free(context->filter_string);

  free(context);
}

static DAQ_State pfring_daq_check_status(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->state;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(update_hw_stats(context) != DAQ_SUCCESS)
    return DAQ_ERROR;

  memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));

  return DAQ_SUCCESS;
}

static void pfring_daq_reset_stats(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  pfring_stat ps;

  memset(&context->stats, 0, sizeof(DAQ_Stats_t));

  if(!context->ring_handle)
    return;

  memset(&ps, 0, sizeof(pfring_stat));
  if(context->ring_handle
     && context->device
     && pfring_stats(context->ring_handle, &ps) == 0) {
    context->base_recv[0] = ps.recv;
    context->base_drop[0] = ps.drop;
  }

  if(context->twin_ring_handle
     && context->twin_device
     && pfring_stats(context->twin_ring_handle, &ps) == 0) {
    context->base_recv[1] = ps.recv;
    context->base_drop[1] = ps.drop;
  }
}

static int pfring_daq_get_snaplen(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context->ring_handle)
    return DAQ_ERROR;
  else
    return context->snaplen;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
  return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
    DAQ_CAPA_INJECT_RAW | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BPF;
}

static int pfring_daq_get_datalink_type(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context)
    return DAQ_ERROR;
  else
    return DLT_EN10MB;
}

static const char *pfring_daq_get_errbuf(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->errbuf;
}

static void pfring_daq_set_errbuf(void *handle, const char *string) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!string)
    return;

  DPE(context->errbuf, "%s", string);
}

static int pfring_daq_get_device_index(void *handle, const char *device) {
  return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
  const DAQ_Module_t pfring_daq_module_data =
#endif
  {
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_PF_RING_VERSION,
    .name = "pfring",
    .type = DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = pfring_daq_initialize,
    .set_filter = pfring_daq_set_filter,
    .start = pfring_daq_start,
    .acquire = pfring_daq_acquire,
    .inject = pfring_daq_inject,
    .breakloop = pfring_daq_breakloop,
    .stop = pfring_daq_stop,
    .shutdown = pfring_daq_shutdown,
    .check_status = pfring_daq_check_status,
    .get_stats = pfring_daq_get_stats,
    .reset_stats = pfring_daq_reset_stats,
    .get_snaplen = pfring_daq_get_snaplen,
    .get_capabilities = pfring_daq_get_capabilities,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .get_errbuf = pfring_daq_get_errbuf,
    .set_errbuf = pfring_daq_set_errbuf,
    .get_device_index = pfring_daq_get_device_index
  };
