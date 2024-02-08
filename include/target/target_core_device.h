#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef TARGET_CORE_DEVICE_H
#define TARGET_CORE_DEVICE_H

extern se_global_t *se_global;

extern struct block_device *__linux_blockdevice_claim(int, int, void *, int *);
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);
#ifndef MY_ABC_HERE
extern int se_check_devices_access(se_hba_t *);
#endif
extern void se_disable_devices_for_hba(se_hba_t *);
extern int transport_get_lun_for_cmd(struct se_cmd_s *, unsigned char *, u32);
extern int transport_get_lun_for_tmr(struct se_cmd_s *, u32);
extern struct se_dev_entry_s *core_get_se_deve_from_rtpi(
					struct se_node_acl_s *, u16);
extern int core_free_device_list_for_node(se_node_acl_t *,
					se_portal_group_t *);
extern void core_dec_lacl_count(struct se_node_acl_s *, struct se_cmd_s *);
extern void core_update_device_list_access(u32, u32, se_node_acl_t *);
extern int core_update_device_list_for_node(se_lun_t *, se_lun_acl_t *, u32,
					u32, se_node_acl_t *,
					se_portal_group_t *, int);
extern void core_clear_lun_from_tpg(se_lun_t *, se_portal_group_t *);
extern struct se_port_s *core_alloc_port(struct se_device_s *);
extern void core_export_port(struct se_device_s *, struct se_portal_group_s *,
					struct se_port_s *, struct se_lun_s *);
extern void core_release_port(struct se_device_s *, struct se_port_s *);
extern int transport_core_report_lun_response(se_cmd_t *);
extern void se_release_device_for_hba(se_device_t *);
extern void se_release_vpd_for_dev(se_device_t *);
extern void se_clear_dev_ports(se_device_t *);
extern int se_free_virtual_device(se_device_t *, se_hba_t *);
extern void se_dev_start(se_device_t *);
extern void se_dev_stop(se_device_t *);
#ifdef MY_ABC_HERE
extern void se_deve_force_readonly(struct se_dev_entry_s *);
#endif
extern void se_dev_set_default_attribs(se_device_t *);
extern int se_dev_set_task_timeout(se_device_t *, u32);
extern int se_dev_set_emulate_ua_intlck_ctrl(se_device_t *, int);
extern int se_dev_set_emulate_tas(se_device_t *, int);
extern int se_dev_set_enforce_pr_isids(se_device_t *, int);
extern int se_dev_set_queue_depth(se_device_t *, u32);
extern int se_dev_set_max_sectors(se_device_t *, u32);
extern int se_dev_set_block_size(se_device_t *, u32);
extern se_lun_t *core_dev_add_lun(se_portal_group_t *, se_hba_t *,
					se_device_t *, u32);
extern int core_dev_del_lun(se_portal_group_t *, u32);
extern se_lun_t *core_get_lun_from_tpg(se_portal_group_t *, u32);
extern se_lun_acl_t *core_dev_init_initiator_node_lun_acl(se_portal_group_t *,
							u32, char *, int *);
extern int core_dev_add_initiator_node_lun_acl(se_portal_group_t *,
						se_lun_acl_t *, u32, u32);
extern int core_dev_del_initiator_node_lun_acl(se_portal_group_t *,
						se_lun_t *, se_lun_acl_t *);
extern void core_dev_free_initiator_node_lun_acl(se_portal_group_t *,
						se_lun_acl_t *lacl);
extern int core_dev_setup_virtual_lun0(void);
extern void core_dev_release_virtual_lun0(void);

#endif  
