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
	{ 0x61ade042, "kmalloc_caches" },
	{ 0xb8952e9c, "pci_bus_read_config_byte" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0x64cd003a, "mem_map" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xb85f3bbe, "pv_lock_ops" },
	{ 0xa90c928a, "param_ops_int" },
	{ 0x91eb9b4, "round_jiffies" },
	{ 0x2b1ea21b, "skb_pad" },
	{ 0x1b51953e, "page_address" },
	{ 0xba27cea9, "dev_set_drvdata" },
	{ 0xb59cd00a, "dma_set_mask" },
	{ 0x2c4b8b06, "napi_complete" },
	{ 0x246fcd96, "pci_disable_device" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0xd553b02, "netif_carrier_on" },
	{ 0x611832cc, "ethtool_op_get_sg" },
	{ 0x8949858b, "schedule_work" },
	{ 0xa40a665d, "netif_carrier_off" },
	{ 0x4205ad24, "cancel_work_sync" },
	{ 0x6ad6e329, "x86_dma_fallback_dev" },
	{ 0xeae3dfd6, "__const_udelay" },
	{ 0x61df2020, "pci_release_regions" },
	{ 0x9e1bdc28, "init_timer_key" },
	{ 0x999e8297, "vfree" },
	{ 0x9a10f02a, "pci_bus_write_config_word" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0x17fad347, "__alloc_pages_nodemask" },
	{ 0x268e0664, "netif_napi_del" },
	{ 0x7d11c268, "jiffies" },
	{ 0xb06ae9b2, "skb_trim" },
	{ 0xdd6d4c74, "__netdev_alloc_skb" },
	{ 0xd1ef871f, "__pskb_pull_tail" },
	{ 0x644f1abc, "pci_set_master" },
	{ 0xe1bc7ede, "del_timer_sync" },
	{ 0x2bc95bd4, "memset" },
	{ 0x2c963f1b, "pci_restore_state" },
	{ 0x88941a06, "_raw_spin_unlock_irqrestore" },
	{ 0x50eedeb8, "printk" },
	{ 0xdd61eb4, "free_netdev" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0xdaba1141, "register_netdev" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x2327bb20, "__pci_enable_wake" },
	{ 0xed93f29e, "__kunmap_atomic" },
	{ 0x4693fcff, "dev_close" },
	{ 0xce095088, "mod_timer" },
	{ 0xa7e255, "netif_napi_add" },
	{ 0xbfcacb59, "dma_release_from_coherent" },
	{ 0xfda85a7d, "request_threaded_irq" },
	{ 0x1ed1de09, "dev_kfree_skb_any" },
	{ 0xdb7d2224, "contig_page_data" },
	{ 0x9fa25542, "dma_alloc_from_coherent" },
	{ 0xe5a17274, "dev_open" },
	{ 0xe523ad75, "synchronize_irq" },
	{ 0x5c1b4e08, "pci_find_capability" },
	{ 0xcf68deb8, "pci_set_mwi" },
	{ 0x7dceceac, "capable" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0x46e6cdd, "netif_device_attach" },
	{ 0xbb321182, "napi_gro_receive" },
	{ 0xf7575791, "netif_device_detach" },
	{ 0x12c9bcd1, "__alloc_skb" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0xc00918ed, "pci_bus_read_config_word" },
	{ 0xa9fc140a, "ethtool_op_set_sg" },
	{ 0x1b134b94, "__napi_schedule" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0x6fc2a1f0, "eth_type_trans" },
	{ 0xa22033d9, "pskb_expand_head" },
	{ 0xcec9c2a4, "pci_unregister_driver" },
	{ 0xcc5005fe, "msleep_interruptible" },
	{ 0xabc328f0, "kmem_cache_alloc_trace" },
	{ 0x6443d74d, "_raw_spin_lock" },
	{ 0x587c70d8, "_raw_spin_lock_irqsave" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0xfc69e635, "pci_set_power_state" },
	{ 0xed95ea5d, "eth_validate_addr" },
	{ 0xcc5b510d, "pci_clear_mwi" },
	{ 0xfcec0987, "enable_irq" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x90395a7f, "___pskb_trim" },
	{ 0xf0cc809, "pci_request_regions" },
	{ 0xd1329880, "param_array_ops" },
	{ 0x4db7b6a8, "dma_supported" },
	{ 0xedc03953, "iounmap" },
	{ 0x1df65373, "pci_prepare_to_sleep" },
	{ 0xe726fb17, "__pci_register_driver" },
	{ 0x2288378f, "system_state" },
	{ 0xe3b22412, "put_page" },
	{ 0xca212ed, "unregister_netdev" },
	{ 0x529e7e26, "ethtool_op_get_tso" },
	{ 0xdf58c688, "__netif_schedule" },
	{ 0x7b4d76b1, "consume_skb" },
	{ 0x85670f1d, "rtnl_is_locked" },
	{ 0xbbf0cc9, "vlan_gro_receive" },
	{ 0xd6eb9777, "skb_put" },
	{ 0x45850bef, "pci_enable_device" },
	{ 0xa5fe2087, "pci_wake_from_d3" },
	{ 0x13095525, "param_ops_uint" },
	{ 0x6678d8f4, "dev_get_drvdata" },
	{ 0x6e720ff2, "rtnl_unlock" },
	{ 0x9e7d6bd0, "__udelay" },
	{ 0xbdb53c5a, "dma_ops" },
	{ 0x47552420, "device_set_wakeup_enable" },
	{ 0xf20dabd8, "free_irq" },
	{ 0xe554d8e3, "pci_save_state" },
	{ 0xe914e41e, "strcpy" },
	{ 0x5ef6a0f0, "alloc_etherdev_mqs" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

MODULE_ALIAS("pci:v00008086d00001000sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001001sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001004sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001008sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001009sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000100Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000100Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000100Esv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000100Fsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001010sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001011sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001012sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001013sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001014sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001015sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001016sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001017sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001018sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001019sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000101Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000101Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000101Esv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001026sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001027sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001028sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001075sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001076sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001077sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001078sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001079sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000107Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000107Bsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000107Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000108Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001099sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010B5sv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "412AFCE4D94BA551C1389A9");
