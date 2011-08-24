#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xca5bc4d1, "module_layout" },
	{ 0xd5d5351d, "__kmap_atomic" },
	{ 0x3ce4ca6f, "disable_irq" },
	{ 0xeea1d3d9, "netdev_info" },
	{ 0x61ade042, "kmalloc_caches" },
	{ 0xb8952e9c, "pci_bus_read_config_byte" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0x57312049, "__pm_runtime_idle" },
	{ 0x64cd003a, "mem_map" },
	{ 0xa90c928a, "param_ops_int" },
	{ 0x91eb9b4, "round_jiffies" },
	{ 0xdab0b5af, "netdev_notice" },
	{ 0xd0d8621b, "strlen" },
	{ 0x1b51953e, "page_address" },
	{ 0xba27cea9, "dev_set_drvdata" },
	{ 0xb59cd00a, "dma_set_mask" },
	{ 0x2c4b8b06, "napi_complete" },
	{ 0x246fcd96, "pci_disable_device" },
	{ 0xf88a41ba, "pci_disable_msix" },
	{ 0xd553b02, "netif_carrier_on" },
	{ 0x53652b01, "pm_qos_add_request" },
	{ 0xe3a2c7b2, "pm_qos_remove_request" },
	{ 0x611832cc, "ethtool_op_get_sg" },
	{ 0x8949858b, "schedule_work" },
	{ 0xa40a665d, "netif_carrier_off" },
	{ 0x4205ad24, "cancel_work_sync" },
	{ 0x6ad6e329, "x86_dma_fallback_dev" },
	{ 0xeae3dfd6, "__const_udelay" },
	{ 0x9e1bdc28, "init_timer_key" },
	{ 0x4df0270, "mutex_unlock" },
	{ 0x18a968e2, "__pm_runtime_resume" },
	{ 0x999e8297, "vfree" },
	{ 0x9a10f02a, "pci_bus_write_config_word" },
	{ 0x17fad347, "__alloc_pages_nodemask" },
	{ 0x7d11c268, "jiffies" },
	{ 0xb06ae9b2, "skb_trim" },
	{ 0xdd6d4c74, "__netdev_alloc_skb" },
	{ 0xd1ef871f, "__pskb_pull_tail" },
	{ 0x644f1abc, "pci_set_master" },
	{ 0xe1bc7ede, "del_timer_sync" },
	{ 0x2bc95bd4, "memset" },
	{ 0x1e17ab0b, "pci_enable_pcie_error_reporting" },
	{ 0xe3e458fd, "pci_enable_msix" },
	{ 0x2c963f1b, "pci_restore_state" },
	{ 0xad9bd82c, "dev_err" },
	{ 0x50eedeb8, "printk" },
	{ 0xa2f5ca2a, "ethtool_op_get_link" },
	{ 0xdd61eb4, "free_netdev" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0xdaba1141, "register_netdev" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x2327bb20, "__pci_enable_wake" },
	{ 0xc637b470, "mutex_lock" },
	{ 0xa34f1ef5, "crc32_le" },
	{ 0xed93f29e, "__kunmap_atomic" },
	{ 0x4693fcff, "dev_close" },
	{ 0xce095088, "mod_timer" },
	{ 0xa7e255, "netif_napi_add" },
	{ 0xbfcacb59, "dma_release_from_coherent" },
	{ 0xfda85a7d, "request_threaded_irq" },
	{ 0x99aacbf9, "ethtool_op_get_flags" },
	{ 0x1ed1de09, "dev_kfree_skb_any" },
	{ 0xdb7d2224, "contig_page_data" },
	{ 0x9fa25542, "dma_alloc_from_coherent" },
	{ 0xe5a17274, "dev_open" },
	{ 0xe523ad75, "synchronize_irq" },
	{ 0x5c1b4e08, "pci_find_capability" },
	{ 0xd0bf115e, "dev_kfree_skb_irq" },
	{ 0x4059792f, "print_hex_dump" },
	{ 0xc0389a99, "pci_select_bars" },
	{ 0x46e6cdd, "netif_device_attach" },
	{ 0xbb321182, "napi_gro_receive" },
	{ 0xd3fa7a74, "_dev_info" },
	{ 0xa9461eb0, "pci_disable_link_state" },
	{ 0xf7575791, "netif_device_detach" },
	{ 0x12c9bcd1, "__alloc_skb" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0xc00918ed, "pci_bus_read_config_word" },
	{ 0xa9fc140a, "ethtool_op_set_sg" },
	{ 0x1b134b94, "__napi_schedule" },
	{ 0xc3c7f921, "pci_cleanup_aer_uncorrect_error_status" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xe00390fc, "pm_schedule_suspend" },
	{ 0x6fc2a1f0, "eth_type_trans" },
	{ 0xa22033d9, "pskb_expand_head" },
	{ 0x721a6a7f, "netdev_err" },
	{ 0xcec9c2a4, "pci_unregister_driver" },
	{ 0xcc5005fe, "msleep_interruptible" },
	{ 0xabc328f0, "kmem_cache_alloc_trace" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0xfc69e635, "pci_set_power_state" },
	{ 0x746bb47b, "netdev_warn" },
	{ 0xed95ea5d, "eth_validate_addr" },
	{ 0x1188a316, "pci_disable_pcie_error_reporting" },
	{ 0xfcec0987, "enable_irq" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x90395a7f, "___pskb_trim" },
	{ 0xd1329880, "param_array_ops" },
	{ 0x9ea3450f, "pci_disable_msi" },
	{ 0x4db7b6a8, "dma_supported" },
	{ 0xedc03953, "iounmap" },
	{ 0x1df65373, "pci_prepare_to_sleep" },
	{ 0x7875029d, "pci_dev_run_wake" },
	{ 0xe726fb17, "__pci_register_driver" },
	{ 0x2288378f, "system_state" },
	{ 0x4e6c1c15, "pm_qos_update_request" },
	{ 0xe3b22412, "put_page" },
	{ 0x3566b87, "dev_warn" },
	{ 0xca212ed, "unregister_netdev" },
	{ 0x529e7e26, "ethtool_op_get_tso" },
	{ 0x9e0c711d, "vzalloc_node" },
	{ 0x701d0ebd, "snprintf" },
	{ 0x1bbc70f7, "pci_enable_msi_block" },
	{ 0xdf58c688, "__netif_schedule" },
	{ 0x7b4d76b1, "consume_skb" },
	{ 0xf24b45a, "pci_enable_device_mem" },
	{ 0xbbf0cc9, "vlan_gro_receive" },
	{ 0xd6eb9777, "skb_put" },
	{ 0xa5fe2087, "pci_wake_from_d3" },
	{ 0x66725887, "pci_release_selected_regions" },
	{ 0x13095525, "param_ops_uint" },
	{ 0x6678d8f4, "dev_get_drvdata" },
	{ 0x9e7d6bd0, "__udelay" },
	{ 0xbdb53c5a, "dma_ops" },
	{ 0xbce8f729, "pci_request_selected_regions_exclusive" },
	{ 0x47552420, "device_set_wakeup_enable" },
	{ 0xf20dabd8, "free_irq" },
	{ 0xe554d8e3, "pci_save_state" },
	{ 0x5ef6a0f0, "alloc_etherdev_mqs" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

MODULE_ALIAS("pci:v00008086d0000105Esv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000105Fsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010A4sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010BCsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010A5sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001060sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010D9sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DAsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010D5sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010B9sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000107Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000107Esv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000107Fsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000108Bsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000108Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000109Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010D3sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001096sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010BAsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001098sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010BBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000104Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C5sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C4sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000104Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000104Bsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000104Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001049sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001501sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C0sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C2sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C3sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010BDsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000294Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010E5sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010BFsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F5sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010CBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010CCsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010CDsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010CEsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DEsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DFsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001525sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010EAsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010EBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010EFsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F0sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001502sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001503sv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "F5E2C2E12FDC7DA19F228FA");
