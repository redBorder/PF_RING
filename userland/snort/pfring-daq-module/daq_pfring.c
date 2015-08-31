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
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include "pfring.h"
#include "sfbpf.h"
#include "daq_api.h"

#ifdef HAVE_REDIS
#include "hiredis/hiredis.h"
#endif

#define DAQ_PF_RING_VERSION 1

#define DAQ_PF_RING_DEFAULT_WATERMARK 128
#define DAQ_PF_RING_DEFAULT_IDLE_RULES_TIMEOUT 300 /* 5 minutes */

#define DAQ_PF_RING_MAX_NUM_DEVICES 64
#define DAQ_PF_RING_PASSIVE_DEV_IDX  0

#define DAQ_PF_RING_BEST_EFFORT_BOOST
#define DAQ_PF_RING_SOFT_BYPASS_BOOST

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
#define DAQ_PF_RING_BEST_EFFORT_BOOST_MIN_NUM_SLOTS 4096
#define DAQ_PF_RING_BEST_EFFORT_BOOST_MAX_STATS_FILE_SIZE (1024*1024)

typedef struct _pfring_queue_slothdr
{
  u_int32_t caplen;
  u_int32_t pktlen;
  int device_index;
  struct timeval ts;
  void *user;
  u_char pkt_buffer[];
} Pfring_Queue_SlotHdr_t;

typedef struct _pfring_queue 
{
  u_char *buffer;
  u_int64_t buffer_len;
  u_int64_t insert_off;
  u_int64_t remove_off;
  u_int32_t tot_read;
  u_int32_t tot_insert;
  u_int32_t tot_dropped;
  u_int32_t max_slot_len;
  u_int32_t min_num_slots;
} Pfring_Queue_t;
#endif

typedef struct _pfring_context
{
  DAQ_Mode mode;
  char *devices[DAQ_PF_RING_MAX_NUM_DEVICES];
  int ifindexes[DAQ_PF_RING_MAX_NUM_DEVICES];
  pfring *ring_handles[DAQ_PF_RING_MAX_NUM_DEVICES];
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  const char *best_effort_stats_file_path;
  FILE *best_effort_stats_file;
  ssize_t besteffort_stats_max_file_size;
#endif
  int num_devices;
  int snaplen;
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  Pfring_Queue_t *q;
#endif
  char *filter_string;
  char errbuf[1024];
  u_char *pkt_buffer;
  u_int breakloop;
  int promisc_flag;
  int timeout;
  int watermark;
  int best_effort; /// @TODO wrap with DAQ_PF_RING_BEST_EFFORT_BOOST
  u_int16_t filter_count;
  DAQ_Analysis_Func_t analysis_func;
  uint32_t netmask;
  DAQ_Stats_t stats;
  u_int clusterids[DAQ_PF_RING_MAX_NUM_DEVICES];
  int num_reflector_devices;
  char *reflector_devices[DAQ_PF_RING_MAX_NUM_DEVICES];
  u_int8_t use_kernel_filters;
  int idle_rules_timeout;
  u_int8_t use_fast_tx;
  cluster_type cluster_mode;
  u_int bindcpu;
  uint64_t base_recv[DAQ_PF_RING_MAX_NUM_DEVICES];
  uint64_t base_drop[DAQ_PF_RING_MAX_NUM_DEVICES];
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  uint64_t base_best_effort_drops;
#endif
#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
  struct{
    char *software_bypass_log;
    FILE *software_bypass_log_f;
    u_int64_t pkts_bypassed;
    u_int64_t base_pkts_bypassed;
    u_int16_t sampling_rate;
    u_int16_t upper_threshold;
    u_int16_t lower_threshold;
    u_int8_t enabled;
  }sw_bypass;
#endif
  DAQ_State state;
#ifdef HAVE_REDIS
  redisContext *redis_ctx;
  char *redis_ip;
  int redis_port;
#endif

} Pfring_Context_t;

static void pfring_daq_reset_stats(void *handle);
static int pfring_daq_set_filter(void *handle, const char *filter);
static void update_best_effort_stats(Pfring_Context_t *context);

#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
static int is_bypass_enabled(const Pfring_Context_t *context){
  return context->sw_bypass.enabled;
}

static void disable_bypass(Pfring_Context_t *context){
  context->sw_bypass.enabled = 0;
}

static void enable_bypass(Pfring_Context_t *context){
  context->sw_bypass.enabled = 1;
}

static uint64_t pfring_daq_total_queued(Pfring_Context_t *context) {
  int i;
  uint64_t total_queued = 0;

  for (i = 0; i < context->num_devices; i++){
    if(context->ring_handles[i])
       total_queued += pfring_get_num_queued_pkts(context->ring_handles[i]);
  }

  return total_queued;
}

/// @TODO merge with software_bypass_log
static void software_bypass_stats_print_line(Pfring_Context_t *context) {
  if(context->sw_bypass.software_bypass_log_f
      && context->sw_bypass.pkts_bypassed > context->sw_bypass.base_pkts_bypassed){
    fseek(context->sw_bypass.software_bypass_log_f, 0, SEEK_SET);
    const int written = fprintf(context->sw_bypass.software_bypass_log_f,"%lu\n",
      context->sw_bypass.pkts_bypassed);
    fflush(context->best_effort_stats_file);
    if(written < 0){
        /* Can't write */

    } else {
        context->sw_bypass.base_pkts_bypassed = context->sw_bypass.pkts_bypassed;
    }
  } else {
    /* @TODO try to reopen? */
  }
}

static void update_soft_bypass_status(Pfring_Context_t *context){
  const uint32_t num_queued_packets = pfring_daq_total_queued(context);
  //printf("%tu Number of queued packets: %u\n",time(NULL),num_queued_packets);

  if(!is_bypass_enabled(context)){ /* bypass off. Should we set it on? */
    if(num_queued_packets > context->sw_bypass.upper_threshold){
      enable_bypass(context);
    }
  }else{ /* We are in bypass time. Should we set it off? */
    if(num_queued_packets < context->sw_bypass.lower_threshold){
      disable_bypass(context);
      software_bypass_stats_print_line(context);
    }
  }
}

#endif

static int pfring_daq_open(Pfring_Context_t *context, int id) {
  uint32_t default_net = 0xFFFFFF00;
  char *device = context->devices[id];
  int pfring_rc;
  pfring *ring_handle;
  char buf[32];

  if(!device) {
    DPE(context->errbuf, "%s", "PF_RING a device must be specified");
    return -1;
  }

  if(device) {
    if(strncmp(device, "dna", 3) == 0) {
      DPE(context->errbuf, "DNA is not supported by daq_pfring. Please get daq_pfring_dna from http://shop.ntop.org");
      return(-1);
    }

    context->pkt_buffer = NULL;

    ring_handle = pfring_open(device, context->snaplen,
			      PF_RING_LONG_HEADER 
			      | (context->promisc_flag ? PF_RING_PROMISC : 0)
			      | (context->use_fast_tx ? PF_RING_RX_PACKET_BOUNCE : 0)
			      );

    if(!ring_handle) {
      DPE(context->errbuf, "pfring_open(): unable to open device '%s'. Please use -i <device>", device);
      return -1;
    }
  }

  pfring_get_bound_device_ifindex(ring_handle, &context->ifindexes[id]);

  /* TODO this is because rules purging is not yet available with hw rules */
  pfring_set_filtering_mode(ring_handle, software_only);

  if (context->mode == DAQ_MODE_INLINE) {
    /* Default mode: recv_and_send_mode */
    pfring_set_direction(ring_handle, rx_only_direction);
  } else if ( context->mode == DAQ_MODE_PASSIVE && !context->best_effort) {
    /* Default direction: rx_and_tx_direction */
    if(context->num_reflector_devices > id) { /* lowlevelbridge ON */
      filtering_rule rule;
      memset(&rule, 0, sizeof(rule));
      rule.rule_id = 1;
      rule.rule_action = reflect_packet_and_continue_rule_evaluation;
      snprintf(rule.reflector_device_name, REFLECTOR_NAME_LEN, "%s", context->reflector_devices[id]);
      if(pfring_add_filtering_rule(ring_handle, &rule) < 0) {
        DPE(context->errbuf, "unable to set the low level packet reflector %s -> %s", device, rule.reflector_device_name);
	pfring_close(ring_handle);
        return -1;
      } else
        printf("%s -> %s\n", context->devices[id], context->reflector_devices[id]);

      pfring_set_direction(ring_handle, rx_only_direction);
    }
    pfring_set_socket_mode(ring_handle, recv_only_mode);
  }

  if(context->clusterids[id] > 0) {
    pfring_rc = pfring_set_cluster(ring_handle, context->clusterids[id], context->cluster_mode);

    if(pfring_rc != 0) {
      DPE(context->errbuf, "pfring_set_cluster returned %d", pfring_rc);
      pfring_close(ring_handle);
      return -1;
    }

    snprintf(buf, sizeof(buf), "snort-cluster-%d-socket-%d", context->clusterids[id], id);
    pfring_set_application_name(ring_handle, buf);
  } else {
    snprintf(buf, sizeof(buf), "snort-socket-%d", id);
    pfring_set_application_name(ring_handle, buf);
  }

  pfring_set_poll_watermark(ring_handle, context->watermark);

  context->netmask = htonl(default_net);

  context->ring_handles[id] = ring_handle;
  return(0);
}

static int update_hw_stats(Pfring_Context_t *context) {
  pfring_stat ps;
  int i;

  for (i = 0; i < context->num_devices; i++)
    if (context->ring_handles[i] == NULL)
      /* daq stopped - using last available stats */
      return DAQ_SUCCESS;

  context->stats.hw_packets_received = 0;
  context->stats.hw_packets_dropped = 0;

  for (i = 0; i < context->num_devices; i++) {
    memset(&ps, 0, sizeof(pfring_stat));

    if(pfring_stats(context->ring_handles[i], &ps) < 0) {
      DPE(context->errbuf, "%s: pfring_stats error [ring_idx = %d]", __FUNCTION__, i);
      return DAQ_ERROR;
    }

    context->stats.hw_packets_received += (ps.recv - context->base_recv[i]);
    context->stats.hw_packets_dropped  += (ps.drop - context->base_drop[i]);
  }

  return DAQ_SUCCESS;
}

static sighandler_t default_sig_reload_handler = NULL;
static u_int8_t pfring_daq_reload_requested = 0;

static void pfring_daq_sig_reload(int sig) {
  if(default_sig_reload_handler != NULL)
    default_sig_reload_handler(sig);

  pfring_daq_reload_requested = 1;
}

static void pfring_daq_reload(Pfring_Context_t *context) {
  int i;

  pfring_daq_reload_requested = 0;

  if (context->use_kernel_filters) {
    for (i = 0; i < context->num_devices; i++) {
      if(context->ring_handles[i] != NULL) {
        pfring_purge_idle_hash_rules(context->ring_handles[i], 0 /* all */);
      }
    }
  }
}

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST

static void close_best_effort_stats(Pfring_Context_t *context) {
  fclose(context->best_effort_stats_file);
}

#endif

#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST

static void close_soft_bypass_stats(Pfring_Context_t *context) {
  fclose(context->sw_bypass.software_bypass_log_f);
}

#endif

static int pfring_daq_initialize(const DAQ_Config_t *config,
				 void **ctxt_ptr, char *errbuf, size_t len) {
  char *clusters = NULL;
  Pfring_Context_t *context;
  DAQ_Dict* entry;
  int i;
  /* taken from pfcount example */
  u_int numCPU = get_nprocs();

  context = calloc(1, sizeof(Pfring_Context_t));
  if(!context) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
    return DAQ_ERROR_NOMEM;
  }

  context->mode = config->mode;
  context->snaplen = config->snaplen;
  context->promisc_flag =(config->flags & DAQ_CFG_PROMISC);
  context->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
  context->watermark = DAQ_PF_RING_DEFAULT_WATERMARK;
  context->filter_count = 0;
  context->use_kernel_filters = 1;
  context->idle_rules_timeout = DAQ_PF_RING_DEFAULT_IDLE_RULES_TIMEOUT;
  context->use_fast_tx = 0;
  context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX] = strdup(config->name);
  context->num_devices = 1;
  context->cluster_mode = cluster_per_flow_2_tuple;
#ifdef HAVE_REDIS
  context->redis_port = -1;
#endif
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  u_int32_t best_effort_min_num_slots = DAQ_PF_RING_BEST_EFFORT_BOOST_MIN_NUM_SLOTS;
  context->besteffort_stats_max_file_size = DAQ_PF_RING_BEST_EFFORT_BOOST_MAX_STATS_FILE_SIZE;
#endif

  if(!context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX]) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
    free(context);
    return DAQ_ERROR_NOMEM;
  }

  for(entry = config->values; entry; entry = entry->next) {
    if(!entry->value || !*entry->value) {
      snprintf(errbuf, len,
	       "%s: variable needs value(%s)\n", __FUNCTION__, entry->key);
      return DAQ_ERROR;
    } else if(!strcmp(entry->key, "clusterid")) {
      clusters = strdup(entry->value);
    } else if(!strcmp(entry->key, "no-kernel-filters")) {
      context->use_kernel_filters = 0;
    } else if(!strcmp(entry->key, "kernel-filters-idle-timeout")) {
      char* end = entry->value;
      context->idle_rules_timeout = (int) strtol(entry->value, &end, 0);
      if(*end || (context->idle_rules_timeout < 0)) {
	snprintf(errbuf, len, "%s: bad kernel filters idle timeout(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key, "fast-tx")) {
      context->use_fast_tx = 1;
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
    } else if(!strcmp(entry->key, "timeout")) {
      char* end = entry->value;
      context->timeout = (int) strtol(entry->value, &end, 0);
      if(*end || (context->timeout < 0)) {
	snprintf(errbuf, len, "%s: bad timeout(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    }
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
    else if(!strcmp(entry->key, "besteffort")) {
      context->best_effort = 1;
    } else if(!strcmp(entry->key, "besteffort_minnumslots")) {
      char* end = NULL;
      best_effort_min_num_slots = strtol(entry->value, &end, 0);
      if(end==entry->value || *end != '\0') {
        snprintf(errbuf, len, "%s: bad best effort min number of slots(%s)\n",
                 __FUNCTION__, entry->value);
        return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key, "besteffort_logfile")) {
      context->best_effort_stats_file_path = strdup(entry->value);
    } else if(!strcmp(entry->key, "besteffort_maxfilesize")) {
      char* end = NULL;
      context->besteffort_stats_max_file_size = strtol(entry->value, &end, 0);
      if(end==entry->value || *end != '\0') {
        snprintf(errbuf, len, "%s: bad best effort max file size(%s)\n",
                 __FUNCTION__, entry->value);
        return DAQ_ERROR;
      }
    }
#endif
    else if(!strcmp(entry->key, "watermark")) {
      char* end = entry->value;
      context->watermark = (int) strtol(entry->value, &end, 0);
      if(*end || (context->watermark < 0)) {
	snprintf(errbuf, len, "%s: bad watermark(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key, "clustermode")) {
      char* end = entry->value;
      int cmode = (int) strtol(entry->value, &end, 0);
      if(*end || (cmode != 2 && cmode != 4 && cmode != 5 && cmode != 6)) {
	snprintf(errbuf, len, "%s: bad cluster mode(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      } else {
        switch (cmode) {
	case 2: context->cluster_mode = cluster_per_flow_2_tuple; break;
	case 4: context->cluster_mode = cluster_per_flow_4_tuple; break;
	case 5: context->cluster_mode = cluster_per_flow_5_tuple; break;
	case 6: context->cluster_mode = cluster_per_flow; break;
	default: break;
	}
      }
    } else if(!strcmp(entry->key, "lowlevelbridge")) {
      if (context->mode == DAQ_MODE_PASSIVE) {
        char *reflector_devices = strdup(entry->value);
        context->num_reflector_devices = 0;
        if (reflector_devices != NULL) {
          /* ethX,ethY */
          char *dev, *dev_pos = NULL;
          dev = strtok_r(reflector_devices, ",", &dev_pos);
          while(dev != NULL) {
            context->reflector_devices[context->num_reflector_devices++] = dev;
            dev = strtok_r(NULL, ",", &dev_pos);
          }
        }
      } else {
        snprintf(errbuf, len, "%s: lowlevelbridge is for passive mode only\n",
		 __FUNCTION__);
        return DAQ_ERROR;
      }
    }
#ifdef HAVE_REDIS
    else if (!strcmp(entry->key, "redis")) {
     char *ipPort = strdup(entry->value);
     if (ipPort != NULL) {
	int i = 0;
	char *temp, *temp2 = NULL;
	temp = strtok_r(ipPort, ":", &temp2);
	while (temp != NULL || i < 2) {
	  if (i == 0)
	    context->redis_ip = strdup(temp);
	  else
	    context->redis_port = atoi(temp);
	  temp = strtok_r(NULL, ":", &temp2);
	  i++;
	}
	if (temp != NULL) {
	  snprintf(errbuf, len, "%s: Incorrect format for <redis ip>:<redis port>\n", __FUNCTION__);
	  free(temp);
	  return DAQ_ERROR;
	}
      }
    }
#endif
    else if(!strcmp(entry->key,"sbypassupperthreshold")) {
      char* end = entry->value;
      context->sw_bypass.upper_threshold = strtol(entry->value, &end, 0);
      if(end==NULL){
	snprintf(errbuf, len, "%s: bad software bypass upper threshold(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key,"sbypasslowerthreshold")) {
      char* end = entry->value;
      context->sw_bypass.lower_threshold = strtol(entry->value, &end, 0);
      if(end==NULL){
	snprintf(errbuf, len, "%s: bad software bypass lower threshold(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key,"sbypasssamplingrate")) {
      char* end = entry->value;
      context->sw_bypass.sampling_rate = strtol(entry->value, &end, 0);
      if(end==NULL){
	snprintf(errbuf, len, "%s: bad software bypass sampling rate(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key,"sbypasslogfile")){
      context->sw_bypass.software_bypass_log = strdup(entry->value);
    } else {
      snprintf(errbuf, len,
	       "%s: unsupported variable(%s=%s)\n",
	       __FUNCTION__, entry->key, entry->value);
      return DAQ_ERROR;
    }
  }

  if(context->mode == DAQ_MODE_READ_FILE) {
    snprintf(errbuf, len, "%s: function not supported on PF_RING", __FUNCTION__);
    free(context);
    return DAQ_ERROR;
  } else if(context->mode == DAQ_MODE_INLINE || 
        (context->mode == DAQ_MODE_PASSIVE && context->best_effort)) {
    /* ethX:ethY;ethZ:ethJ */
    char *twins, *twins_pos = NULL;
    context->num_devices = 0;

    twins = strtok_r(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX], ",", &twins_pos);
    while(twins != NULL) {
      char *dev, *dev_pos = NULL;
      int last_twin = 0;

      dev = strtok_r(twins, ":", &dev_pos);
      while(dev != NULL) {
        last_twin = context->num_devices;

        context->devices[context->num_devices++] = dev;

        dev = strtok_r(NULL, ":", &dev_pos);
      }

      if (context->num_devices & 0x1) {
        snprintf(errbuf, len, "%s: Wrong format: inline mode requires pairs of devices", __FUNCTION__);
        free(context);
        return DAQ_ERROR;
      }

      if (last_twin > 0) /* new dev pair */
        printf("%s <-> %s\n", context->devices[last_twin - 1], context->devices[last_twin]);

      twins = strtok_r(NULL, ",", &twins_pos);
    }
  } else if(context->mode == DAQ_MODE_PASSIVE) {
    /* ethX,ethY */
    char *dev, *dev_pos = NULL;
    context->num_devices = 0;

    dev = strtok_r(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX], ",", &dev_pos);
    while(dev != NULL) {
      if(context->num_devices >= DAQ_PF_RING_MAX_NUM_DEVICES){
        snprintf(errbuf, len, "%s: too many interfaces!", __FUNCTION__);
        free(context);
        return DAQ_ERROR_NOMEM;
      }

      context->devices[context->num_devices++] = dev;
      dev = strtok_r(NULL, ",", &dev_pos);
    }

    if (context->num_reflector_devices > 0 && 
       context->num_reflector_devices != context->num_devices) {
      snprintf(errbuf, len, "%s: not enough reflector devices (%d)\n",
               __FUNCTION__, context->num_reflector_devices);
      return DAQ_ERROR;
    }
  }

  if (clusters != NULL) {
    char *clusterid, *clusterid_pos = NULL;
    char* end;

    clusterid = strtok_r(clusters, ",", &clusterid_pos);
    for (i = 0; i < context->num_devices; i++) {
      if (clusterid == NULL) {
        snprintf(errbuf, len, "%s: not enough cluster ids (%d)\n", __FUNCTION__, i);
        return DAQ_ERROR;
      }

      end = clusters;
      context->clusterids[i] =(int)strtol(clusterid, &end, 0);
      if(*end
         || (context->clusterids[i] <= 0)
         || (context->clusterids[i] > 65535)) {
        snprintf(errbuf, len, "%s: bad clusterid(%s)\n",
                 __FUNCTION__, clusterid);

        return DAQ_ERROR;
      }

      clusterid = strtok_r(NULL, ",", &clusterid_pos);
    }
    free(clusters);
  }

  if(context->sw_bypass.upper_threshold == 0 || context->sw_bypass.lower_threshold == 0)
    context->sw_bypass.sampling_rate = 0; // Disable

  /* catching the SIGRELOAD signal, replacing the default snort handler */
  if ((default_sig_reload_handler = signal(SIGHUP, pfring_daq_sig_reload)) == SIG_ERR)
    default_sig_reload_handler = NULL;

  for (i = 0; i < context->num_devices; i++) {
    if(context->ring_handles[i] == NULL) {
      if (pfring_daq_open(context, i) == -1)
//rb:ini
        //return DAQ_ERROR;
        {
          snprintf(errbuf, len, "%s", context->errbuf);
          return DAQ_ERROR;
        }
//rb:fin
    }
  }

#ifdef HAVE_REDIS
  if (context->redis_ip != NULL && context->redis_port != -1) {
    if ((context->redis_ctx = redisConnect(context->redis_ip, context->redis_port)) == NULL || context->redis_ctx->err) {
      snprintf(errbuf, len, "redis connection error: %d", context->redis_ctx->err);
      return DAQ_ERROR;
    }
  }
#endif

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  if (context->mode == DAQ_MODE_PASSIVE && context->best_effort == 1) {
    context->q = (Pfring_Queue_t *) calloc(1, sizeof(Pfring_Queue_t));
    if(!context->q) {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
      return DAQ_ERROR_NOMEM;
    }

    context->q->min_num_slots = best_effort_min_num_slots;
    context->q->max_slot_len = sizeof(Pfring_Queue_SlotHdr_t) + context->snaplen;
    context->q->buffer_len = context->q->min_num_slots * context->q->max_slot_len;

    context->q->buffer = (u_char *) malloc(context->q->buffer_len);
    if(!context->q->buffer) {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for best-effort IDS bridge support (queue)!", __FUNCTION__);
      return DAQ_ERROR_NOMEM;
    }
  }

  if (NULL != context->best_effort_stats_file_path) {
    char full_filename_buffer[2048];
    const int snprintf_rc = snprintf(full_filename_buffer,sizeof(full_filename_buffer),
                            "%s.%lu",context->best_effort_stats_file_path,time(NULL));
    if(snprintf_rc < 0) {
      snprintf(errbuf, len, "%s: Couldn't use %s base filename for best effort stats!", __FUNCTION__,context->best_effort_stats_file_path);
      return DAQ_ERROR;
    }

    if(snprintf_rc > (ssize_t)sizeof(full_filename_buffer)) {
      snprintf(errbuf, len, "%s: Couldn't use %s base filename for best effort stats: It's too long!", __FUNCTION__,context->best_effort_stats_file_path);
      return DAQ_ERROR;
    }

    context->best_effort_stats_file = fopen(context->best_effort_stats_file_path,"w");
    if(NULL == context->best_effort_stats_file) {
      snprintf(errbuf, len, "%s: Couldn't open %s file for best effort stats!: %s", __FUNCTION__,context->best_effort_stats_file_path,strerror(errno));
      return DAQ_ERROR;
    }
  }
#endif

#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
  /// @TODO merge with best effort log file
  if(context->sw_bypass.software_bypass_log) {
    context->sw_bypass.software_bypass_log_f = fopen(context->sw_bypass.software_bypass_log,"w");
    if(NULL == context->sw_bypass.software_bypass_log_f) {
      snprintf(errbuf, len, "%s: Couldn't open %s file for best effort stats!: %s", __FUNCTION__,context->sw_bypass.software_bypass_log,strerror(errno));
      return DAQ_ERROR;
    } else {
      fprintf(context->sw_bypass.software_bypass_log_f,"0\n");
    }
  }
#endif


  context->state = DAQ_STATE_INITIALIZED;

  *ctxt_ptr = context;
  return DAQ_SUCCESS;
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret, i;
  struct sfbpf_program fcode;

  if(context->ring_handles[DAQ_PF_RING_PASSIVE_DEV_IDX]) {
    if(sfbpf_compile(context->snaplen, DLT_EN10MB, &fcode,
		     filter, 0 /* 1: optimize */, htonl(context->netmask)) < 0) {
      DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
      return DAQ_ERROR;
    }

    ret = DAQ_SUCCESS;
    for (i = 0; i < context->num_devices; i++) {
      if(setsockopt(pfring_get_selectable_fd(context->ring_handles[i]), 0,
		    SO_ATTACH_FILTER, &fcode, sizeof(fcode)) != 0) {
        ret = DAQ_ERROR;
      }
    }

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

  if(context->filter_string) {
    if(pfring_daq_set_filter(context, context->filter_string))
      return DAQ_ERROR;
  }

  pfring_daq_reset_stats(context);
  context->state = DAQ_STATE_STARTED;

  return DAQ_SUCCESS;
}

static int pfring_daq_send_packet(Pfring_Context_t *context, pfring *send_ring,
				  u_int pkt_len, pfring *recv_ring, int send_ifindex)
{
  int rc;

  if(( !context->use_fast_tx && send_ring == NULL)
     ||(context->use_fast_tx && recv_ring == NULL))
    return(DAQ_SUCCESS);

  if(context->use_fast_tx)
    rc = pfring_send_last_rx_packet(recv_ring, send_ifindex);
  else
    rc = pfring_send(send_ring, (char *) context->pkt_buffer, pkt_len, 1 /* flush packet */);

  if (rc < 0) {
    DPE(context->errbuf, "%s", "pfring_send() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;

  return(DAQ_SUCCESS);
}

#ifdef HAVE_REDIS
int pfring_daq_redis_insert_to_set(redisContext *redis_ctx, const char *set_name, char *ip) {
  redisReply *r = NULL;
  const int TTL = 3600;
 
#if 0
  if ((r = redisCommand(redis_ctx, "SISMEMBER %s %s", set_name, ip)) != NULL) {
    if (r->integer != 0) {
      freeReplyObject(r);
      return DAQ_ERROR;
    }
  } else {
    freeReplyObject(r);
    return DAQ_ERROR;
  }
  freeReplyObject(r);
#endif

  if ((r = redisCommand(redis_ctx, "SADD %s %s", set_name, ip)) != NULL) {
    //printf("[DEBUG] Entry added to %s SET: %s\n",set_name,ip);
    freeReplyObject(r);
  } else{
    freeReplyObject(r);
    return DAQ_ERROR;
  }

  if((r = redisCommand(redis_ctx, "INCR %s", ip)) != NULL) {
    //printf("[DEBUG] Incrementing the entry added to %s SET: %s\n",set_name,ip);
    freeReplyObject(r);
  } else {
    freeReplyObject(r);
    return DAQ_ERROR;
  }
  
  if((r = redisCommand(redis_ctx, "EXPIRE %s %d", ip, TTL)) != NULL){
    //printf("[DEBUG] Setting the expire time of %d sec to the entry added to %s SET: %s\n",TTL,set_name,ip);
    freeReplyObject(r);
  } else {
    freeReplyObject(r);
    return DAQ_ERROR;
  }

  return DAQ_SUCCESS;
}
#endif

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
static inline int pfring_daq_queue_check_room(Pfring_Queue_t *q) {
  if (q->insert_off == q->remove_off) {
    if ((q->tot_insert - q->tot_read) >= q->min_num_slots)
      return 0;
  } else {
    if (q->insert_off < q->remove_off) {
      if ((q->remove_off - q->insert_off) < q->max_slot_len)
        return 0;
    } else {
      if ((q->buffer_len - q->insert_off) < q->max_slot_len && q->remove_off == 0)
        return 0;
    }
  }

  return 1;
}

static inline int pfring_daq_queue_next_slot_offset(Pfring_Queue_t *q, 
  u_int32_t off) {
  Pfring_Queue_SlotHdr_t *qhdr = (Pfring_Queue_SlotHdr_t *) &q->buffer[off];
  u_int32_t real_slot_size;

  real_slot_size = sizeof(Pfring_Queue_SlotHdr_t) + qhdr->caplen;

  if((off + real_slot_size + q->max_slot_len) > q->buffer_len)
    return 0;

  return (off + real_slot_size);
}

#define min(_a, _b) ((_a) < (_b) ? (_a) : (_b))

static inline void pfring_daq_enqueue(Pfring_Queue_t *q,
  struct pfring_pkthdr *phdr, u_char* pkt_buffer, u_int32_t ifindex, void *user) {

  if (pfring_daq_queue_check_room(q)) {
    Pfring_Queue_SlotHdr_t *qhdr = (Pfring_Queue_SlotHdr_t *) &q->buffer[q->insert_off];

    qhdr->caplen = min(phdr->caplen, q->max_slot_len - sizeof(Pfring_Queue_SlotHdr_t));
    qhdr->pktlen = phdr->len;
    qhdr->ts = phdr->ts;
    qhdr->device_index = ifindex;

    memcpy(qhdr->pkt_buffer, pkt_buffer, qhdr->caplen);

    q->insert_off = pfring_daq_queue_next_slot_offset(q, q->insert_off);
    q->tot_insert++;
  } else {
    q->tot_dropped++;    
  }
}

static inline int pfring_daq_queue_check_packet(Pfring_Queue_t *q) {
  return q->tot_insert != q->tot_read;
}

static inline Pfring_Queue_SlotHdr_t *pfring_daq_dequeue(Pfring_Queue_t *q) { 
  Pfring_Queue_SlotHdr_t *qhdr = (Pfring_Queue_SlotHdr_t *) &q->buffer[q->remove_off];
  q->remove_off = pfring_daq_queue_next_slot_offset(q, q->remove_off);
  q->tot_read++;
  return qhdr;
}

/// @TODO merge with main pfring_daq_process
static inline void pfring_daq_process(Pfring_Context_t *context, Pfring_Queue_SlotHdr_t *qhdr) {
  DAQ_PktHdr_t hdr;
  DAQ_Verdict verdict;

  hdr.caplen = qhdr->caplen;
  hdr.pktlen = qhdr->pktlen;
  hdr.ts = qhdr->ts;
#if (DAQ_API_VERSION >= 0x00010002)
  hdr.ingress_index = qhdr->device_index;
  hdr.egress_index = -1;
  hdr.ingress_group = -1;
  hdr.egress_group = -1;
#else
  hdr.device_index = qhdr->device_index;
#endif
  hdr.flags = 0;

#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
  if(context->sw_bypass.sampling_rate >0 && 
    (context->stats.packets_received+context->sw_bypass.pkts_bypassed)
        %context->sw_bypass.sampling_rate == 0) {
    update_soft_bypass_status(context);
  }

  if(!is_bypass_enabled(context)) {
#endif
    verdict = context->analysis_func(qhdr->user, &hdr,(u_char*)qhdr->pkt_buffer);
    context->stats.packets_received++;
    context->stats.verdicts[verdict]++;
#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
  } else {
    context->sw_bypass.pkts_bypassed++;
    verdict = DAQ_VERDICT_PASS;
  }
#endif

  if(verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;

  switch(verdict) {
    case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
      /* TODO handle hw filters */
      break;
    case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
    case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */
    case DAQ_VERDICT_PASS:      /* Pass the packet */
    case DAQ_VERDICT_REPLACE:   /* Pass a packet that has been modified in-place.(No resizing allowed!) */
    case DAQ_VERDICT_BLOCK:     /* Block the packet. */
      /* Nothing to do really */
      break;
    case MAX_DAQ_VERDICT:
      /* No way we can reach this point */
      break;
  }
}

static inline int pfring_daq_in_packets(Pfring_Context_t *context, u_int32_t *rx_ring_idx) {
  int i;
  
  for (i = 0; i < context->num_devices; i++) {
    *rx_ring_idx = ((*rx_ring_idx) + 1) % context->num_devices;
    if (context->ring_handles[*rx_ring_idx]->is_pkt_available(context->ring_handles[*rx_ring_idx]) > 0) 
      return 1;
  }

  return 0;
}

static int pfring_daq_acquire_best_effort(void *handle, int cnt, DAQ_Analysis_Func_t callback,
#if (DAQ_API_VERSION >= 0x00010002)
                              DAQ_Meta_Func_t metaback,
#endif
                              void *user) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret = 0, i, rc, poll_duration = 0, c = 0;
  u_int32_t rx_ring_idx = context->num_devices - 1, rx_ring_idx_clone;
  struct pollfd pfd[DAQ_PF_RING_MAX_NUM_DEVICES];
  struct pfring_pkthdr phdr;

  context->analysis_func = callback;
  context->breakloop = 0;

  for (i = 0; i < context->num_devices; i++) {
    //pfring_enable_ring(context->ring_handles[i]);
    pfd[i].fd = pfring_get_selectable_fd(context->ring_handles[i]);
  }

  while((!context->breakloop) && ((cnt <= 0) || (c < cnt))) {

    memset(&phdr, 0, sizeof(phdr));

    if(pfring_daq_reload_requested)
      pfring_daq_reload(context);

    while(pfring_daq_in_packets(context, &rx_ring_idx) && !context->breakloop) {

      pfring_recv(context->ring_handles[rx_ring_idx], &context->pkt_buffer, 0, &phdr, 0);
#if 0
      if(!pfring_daq_in_packets(context, &rx_ring_idx)) { /* optimization (?): no enqueue */
        pfring_daq_process(..);
        c++;
      } else
#endif

#ifdef ENABLE_BPF
      if (!context->bpf_filter || bpf_filter(context->filter.bf_insns, context->pkt_buffer, phdr.caplen, phdr.len) != 0) { /* accept */
#endif
      /* enqueueing pkt (and don't care of no room available) */
      pfring_daq_enqueue(context->q, &phdr, context->pkt_buffer, context->ifindexes[rx_ring_idx], user);
#ifdef ENABLE_BPF
      } else {
        context->stats.packets_received++;
        context->stats.verdicts[DAQ_VERDICT_PASS]++;
      }
#endif

      pfring_daq_send_packet(context, context->ring_handles[rx_ring_idx ^ 0x1], phdr.caplen, 
                                 context->ring_handles[rx_ring_idx], context->ifindexes[rx_ring_idx ^ 0x1]);
    }

    rx_ring_idx_clone = rx_ring_idx;
    while(!(ret = pfring_daq_in_packets(context, &rx_ring_idx_clone)) && pfring_daq_queue_check_packet(context->q) && !context->breakloop) {
      /* no incoming pkts, queued pkts available -> processing enqueued pkts */
      Pfring_Queue_SlotHdr_t *qhdr = pfring_daq_dequeue(context->q); 
      pfring_daq_process(context, qhdr);
      c++;
    }

    if(!ret) {
      /* no packet to read: poll */
      for (i = 0; i < context->num_devices; i++) {
        pfring_sync_indexes_with_kernel(context->ring_handles[i]);
        pfd[i].events = POLLIN;
        pfd[i].revents = 0;
      }

      errno = 0;
      rc = poll(pfd, context->num_devices, poll_duration < context->timeout ? poll_duration += 10 : poll_duration);

      if(rc < 0) {
        if(errno == EINTR)
          break;

        DPE(context->errbuf, "%s: Poll failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
        return DAQ_ERROR;
      } else if (rc > 0) poll_duration = 0;
    }
  }

  return 0;
}
#endif

static int pfring_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, 
#if (DAQ_API_VERSION >= 0x00010002)
                              DAQ_Meta_Func_t metaback,
#endif
			      void *user) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  int ret = 0, i, current_ring_idx = context->num_devices - 1, rx_ring_idx, c = 0;
  struct pollfd pfd[DAQ_PF_RING_MAX_NUM_DEVICES];
  hash_filtering_rule hash_rule;

  memset(&hash_rule, 0, sizeof(hash_rule));

  context->analysis_func = callback;
  context->breakloop = 0;

  for (i = 0; i < context->num_devices; i++)
    pfring_enable_ring(context->ring_handles[i]);

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  if (context->mode == DAQ_MODE_PASSIVE && context->best_effort == 1)
    return pfring_daq_acquire_best_effort(handle, cnt, callback, 
#if (DAQ_API_VERSION >= 0x00010002)
      metaback,
#endif 
      user);
#endif

  while((cnt <= 0) || (c < cnt)) {
    struct pfring_pkthdr phdr;
    DAQ_PktHdr_t hdr;
    DAQ_Verdict verdict;

    if(context->breakloop) {
      context->breakloop = 0;
      return 0;
    }

    memset(&phdr, 0, sizeof(phdr));

    if(pfring_daq_reload_requested)
      pfring_daq_reload(context);

    for (i = 0; i < context->num_devices; i++) {
      current_ring_idx = (current_ring_idx + 1) % context->num_devices;

      ret = pfring_recv(context->ring_handles[current_ring_idx], &context->pkt_buffer, 0, &phdr, 0 /* Dont't wait */);

      if (ret > 0) break;
    }

    if(ret <= 0) {
      /* No packet to read: let's poll */
      int rc;

      for (i = 0; i < context->num_devices; i++) {
        pfd[i].fd = pfring_get_selectable_fd(context->ring_handles[i]);
        pfd[i].events = POLLIN;
	pfd[i].revents = 0;
      }

      rc = poll(pfd, context->num_devices, context->timeout);

      if(rc < 0) {
	if(errno == EINTR)
	  break;

	DPE(context->errbuf, "%s: Poll failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
	return DAQ_ERROR;
      }
    } else {
      hdr.caplen = phdr.caplen;
      hdr.pktlen = phdr.len;
      hdr.ts = phdr.ts;
#if (DAQ_API_VERSION >= 0x00010002)
      hdr.ingress_index = phdr.extended_hdr.if_index;
      hdr.egress_index = -1;
      hdr.ingress_group = -1;
      hdr.egress_group = -1;
#else
      hdr.device_index = phdr.extended_hdr.if_index;
#endif
      hdr.flags = 0;

      rx_ring_idx = current_ring_idx;

#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
      if(context->sw_bypass.sampling_rate >0 && 
            (context->stats.packets_received+context->sw_bypass.pkts_bypassed)
            %context->sw_bypass.sampling_rate == 0) {
          update_soft_bypass_status(context);
      }

      if(!is_bypass_enabled(context)){
#endif
        context->stats.packets_received++;
        verdict = context->analysis_func(user, &hdr,(u_char*)context->pkt_buffer);
#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
      } else {
        context->sw_bypass.pkts_bypassed++;
        verdict = DAQ_VERDICT_PASS;
      }
#endif

#if 0
      printf("[DEBUG] %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d Verdict=%d\n",
         phdr.extended_hdr.parsed_pkt.ipv4_src >> 24 & 0xFF, phdr.extended_hdr.parsed_pkt.ipv4_src >> 16 & 0xFF,
         phdr.extended_hdr.parsed_pkt.ipv4_src >>  8 & 0xFF, phdr.extended_hdr.parsed_pkt.ipv4_src >>  0 & 0xFF,
         phdr.extended_hdr.parsed_pkt.l4_src_port & 0xFFFF,
         phdr.extended_hdr.parsed_pkt.ipv4_dst >> 24 & 0xFF, phdr.extended_hdr.parsed_pkt.ipv4_dst >> 16 & 0xFF,
         phdr.extended_hdr.parsed_pkt.ipv4_dst >>  8 & 0xFF, phdr.extended_hdr.parsed_pkt.ipv4_dst >>  0 & 0xFF,
         phdr.extended_hdr.parsed_pkt.l4_src_port & 0xFFFF,
         verdict);
#endif

      if(verdict >= MAX_DAQ_VERDICT)
	verdict = DAQ_VERDICT_PASS;

      if (phdr.extended_hdr.parsed_pkt.eth_type == 0x0806 /* ARP */ )
        verdict = DAQ_VERDICT_PASS;
      
      switch(verdict) {
      case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
	if (context->use_kernel_filters) {
	  
	  pfring_parse_pkt(context->pkt_buffer, &phdr, 4, 0, 0);
	  /* or use pfring_recv_parsed() to force parsing. */

	  hash_rule.rule_id     = context->filter_count++;
	  hash_rule.vlan_id     = phdr.extended_hdr.parsed_pkt.vlan_id;
	  hash_rule.proto       = phdr.extended_hdr.parsed_pkt.l3_proto;
	  memcpy(&hash_rule.host_peer_a, &phdr.extended_hdr.parsed_pkt.ipv4_src, sizeof(ip_addr));
	  memcpy(&hash_rule.host_peer_b, &phdr.extended_hdr.parsed_pkt.ipv4_dst, sizeof(ip_addr));
	  hash_rule.port_peer_a = phdr.extended_hdr.parsed_pkt.l4_src_port;
	  hash_rule.port_peer_b = phdr.extended_hdr.parsed_pkt.l4_dst_port;
	  hash_rule.plugin_action.plugin_id = NO_PLUGIN_ID;

	  if (context->mode == DAQ_MODE_PASSIVE && context->num_reflector_devices > rx_ring_idx) { /* lowlevelbridge ON */
	    hash_rule.rule_action = reflect_packet_and_stop_rule_evaluation;
	    snprintf(hash_rule.reflector_device_name, REFLECTOR_NAME_LEN, "%s", context->reflector_devices[rx_ring_idx]);
	  } else {
	    hash_rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
	  }

	  pfring_handle_hash_filtering_rule(context->ring_handles[rx_ring_idx], &hash_rule, 1 /* add_rule */);

	  /* Purge rules idle (i.e. with no packet matching) for more than 1h */
	  pfring_purge_idle_hash_rules(context->ring_handles[rx_ring_idx], context->idle_rules_timeout);

#if DEBUG
	  printf("[DEBUG] %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d Verdict=%d Action=%d\n",
	         hash_rule.host_peer_a.v4 >> 24 & 0xFF, hash_rule.host_peer_a.v4 >> 16 & 0xFF,
	         hash_rule.host_peer_a.v4 >>  8 & 0xFF, hash_rule.host_peer_a.v4 >>  0 & 0xFF,
	         hash_rule.port_peer_a & 0xFFFF,
	         hash_rule.host_peer_b.v4 >> 24 & 0xFF, hash_rule.host_peer_b.v4 >> 16 & 0xFF,
	         hash_rule.host_peer_b.v4 >>  8 & 0xFF, hash_rule.host_peer_b.v4 >>  0 & 0xFF,
	         hash_rule.port_peer_b & 0xFFFF,
	         verdict,
		 hash_rule.rule_action);
#endif	  
	}

#ifdef HAVE_REDIS
	if (context->redis_ctx != NULL) {
          char ipAttacker[INET_ADDRSTRLEN];
          char ipTarget[INET_ADDRSTRLEN];

	  pfring_parse_pkt(context->pkt_buffer, &phdr, 4, 0, 0);

	  /* Attacker */
	  if (inet_ntop(AF_INET, (const void *) &phdr.extended_hdr.parsed_pkt.ipv4_src, ipAttacker, INET_ADDRSTRLEN) != NULL) {
	    if (pfring_daq_redis_insert_to_set(context->redis_ctx, "Attackers", ipAttacker) != DAQ_SUCCESS) {
	      DPE(context->errbuf, "%s: Insert into Attackers Set failed: %s", __FUNCTION__, ipAttacker);
	      return DAQ_ERROR;
	    }
	  }
	  
	  /* target */
	  if (inet_ntop(AF_INET,(const void *) &phdr.extended_hdr.parsed_pkt.ipv4_dst, ipTarget, INET_ADDRSTRLEN) != NULL) {
	    if (pfring_daq_redis_insert_to_set(context->redis_ctx, "Targets", ipTarget) != DAQ_SUCCESS) {
	      DPE(context->errbuf, "%s: Insert into Targets Set failed: %s", __FUNCTION__, ipTarget);
	      return DAQ_ERROR;
	    }
	  }
	}
#endif

	break;

      case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
      case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */
        /* Setting a rule for reflectiong packets when lowlevelbridge is ON could be an optimization here, 
	 * but we can't set "forward" (reflector won't work) or "reflect" (packets reflected twice) hash rules */ 
      case DAQ_VERDICT_PASS:      /* Pass the packet */
      case DAQ_VERDICT_REPLACE:   /* Pass a packet that has been modified in-place.(No resizing allowed!) */
        if (context->mode == DAQ_MODE_INLINE) {
	  pfring_daq_send_packet(context, context->ring_handles[rx_ring_idx ^ 0x1], hdr.caplen, 
				 context->ring_handles[rx_ring_idx], context->ifindexes[rx_ring_idx ^ 0x1]);
	}
	break;

      case DAQ_VERDICT_BLOCK:   /* Block the packet. */
	/* Nothing to do really */
	break;

      case MAX_DAQ_VERDICT:
	/* No way we can reach this point */
	break;
      }

      context->stats.verdicts[verdict]++;
      c++;
    }
  }

  return 0;
}

static int pfring_daq_inject(void *handle, const DAQ_PktHdr_t *hdr,
			     const uint8_t *packet_data, uint32_t len, int reverse) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int i, tx_ring_idx = DAQ_PF_RING_PASSIVE_DEV_IDX;

  if (context->mode == DAQ_MODE_INLINE) { /* looking for the device idx */
    for (i = 0; i < context->num_devices; i++)
#if (DAQ_API_VERSION >= 0x00010002)
      if (context->ifindexes[i] == hdr->ingress_index) {
#else
      if (context->ifindexes[i] == hdr->device_index) {
#endif
        tx_ring_idx = i ^ 0x1;
        break;
      }
  }

  if(pfring_send(context->ring_handles[tx_ring_idx],
		 (char *) packet_data, len, 1 /* flush packet */) < 0) {
    DPE(context->errbuf, "%s", "pfring_send() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;
  return DAQ_SUCCESS;
}

static int pfring_daq_breakloop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context->ring_handles[DAQ_PF_RING_PASSIVE_DEV_IDX])
    return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  int i;

  update_hw_stats(context);

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  update_best_effort_stats(context);
#endif

  for (i = 0; i < context->num_devices; i++) {
    if(context->ring_handles[i]) {
      /* Store the hardware stats for post-stop stat calls. */
      pfring_close(context->ring_handles[i]);
      context->ring_handles[i] = NULL;
    }
  }

  context->state = DAQ_STATE_STOPPED;

  return DAQ_SUCCESS;
}

static void pfring_daq_shutdown(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  int i;

  for (i = 0; i < context->num_devices; i++)
    if(context->ring_handles[i])
      pfring_close(context->ring_handles[i]);

  if(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX])
    free(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX]);

  if(context->reflector_devices[DAQ_PF_RING_PASSIVE_DEV_IDX])
    free(context->reflector_devices[DAQ_PF_RING_PASSIVE_DEV_IDX]);

  if(context->filter_string)
    free(context->filter_string);

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  if(context->best_effort_stats_file)
    close_best_effort_stats(context);
#endif

#ifdef DAQ_PF_RING_SOFT_BYPASS_BOOST
  if(context->sw_bypass.software_bypass_log_f)
    close_soft_bypass_stats(context);
#endif

#ifdef HAVE_REDIS
  if(context->redis_ctx != NULL)
    redisFree(context->redis_ctx);
#endif

  if(context->sw_bypass.software_bypass_log)
    free(context->sw_bypass.software_bypass_log);

  free(context);
}

static DAQ_State pfring_daq_check_status(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->state;
}

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
static void best_effort_stats_print_line(Pfring_Context_t *context) {
  if(context->best_effort_stats_file 
        && context->q->tot_dropped > context->base_best_effort_drops) {
    fseek(context->best_effort_stats_file, 0, SEEK_SET);
    const int written = fprintf(context->best_effort_stats_file,"%u\n",
      context->q->tot_dropped);
    fflush(context->best_effort_stats_file);
    if(written < 0){
        /* Can't write */

    } else {
        context->base_best_effort_drops = context->q->tot_dropped;
    }
  } else {
    /* @TODO try to reopen? */
  }
}

static void update_best_effort_stats(Pfring_Context_t *context) {
  best_effort_stats_print_line(context);
}

#endif

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  update_hw_stats(context);

  memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  update_best_effort_stats(context);
#endif

  return DAQ_SUCCESS;
}

static void pfring_daq_reset_stats(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  pfring_stat ps;
  int i;

  memset(&context->stats, 0, sizeof(DAQ_Stats_t));
  memset(&ps, 0, sizeof(pfring_stat));

  for (i = 0; i < context->num_devices; i++)
    if(context->ring_handles[i]
       && pfring_stats(context->ring_handles[i], &ps) == 0) {
      context->base_recv[i] = ps.recv;
      context->base_drop[i] = ps.drop;
    }
}

static int pfring_daq_get_snaplen(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context->ring_handles[DAQ_PF_RING_PASSIVE_DEV_IDX])
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
