/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright 2023 NXP
 *
 *
 */
#ifndef BUZZER_BLUETOOTH_H
#define BUZZER_BLUETOOTH_H

#include "panda/compiler.h"

#include <stdint.h>

#define hci_handle_pack(_h, _f)	((__u16) ((_h & 0x0fff)|(_f << 12)))
#define hci_handle(_h)		(_h & 0x0fff)
#define hci_flags(_h)		(_h >> 12)

#define PB_START_NO_FLUSH           0x00
#define PB_CONT                     0x01
#define PB_START                    0x02
#define PB_COMPLETE                 0x03

#define BT_HCI_CMD_BIT(_byte, _bit) ((8 * _byte) + _bit)

#define BT_H4_CMD_PKT	0x01
#define BT_H4_ACL_PKT	0x02
#define BT_H4_SCO_PKT	0x03
#define BT_H4_EVT_PKT	0x04
#define BT_H4_ISO_PKT	0x05
#define BT_TMOUT 		0xFF

#define LINK_TYPE_SCO	0
#define LINK_TYPE_ACL	1
#define LINK_TYPE_ESCO	2

typedef struct __packed {
	uint16_t opcode;
	uint8_t  plen;
	uint8_t params[];
} bt_hci_cmd_hdr;

typedef struct __packed {
	uint16_t handle;
	uint16_t dlen;
	uint8_t  data[];
} bt_hci_acl_hdr;

typedef struct __packed {
	uint16_t handle;
	uint8_t  dlen;
} bt_hci_sco_hdr;

typedef struct __packed {
	uint16_t handle;
	uint16_t dlen;
	uint8_t  data[];
} bt_hci_iso_hdr;

typedef struct __packed {
	uint16_t sn;
	uint16_t slen;
	uint8_t  data[];
} bt_hci_iso_data_start;

typedef struct __packed {
	uint8_t  evt;
	uint8_t  plen;
	uint8_t	 params[];
} bt_hci_evt_hdr;

#define BT_HCI_CMD_NOP				0x0000

#define BT_HCI_CMD_INQUIRY			0x0401
typedef struct __packed {
	uint8_t  lap[3];
	uint8_t  length;
	uint8_t  num_resp;
} bt_hci_cmd_inquiry;

#define BT_HCI_CMD_INQUIRY_CANCEL		0x0402

#define BT_HCI_CMD_PERIODIC_INQUIRY		0x0403
typedef struct __packed {
	uint16_t max_period;
	uint16_t min_period;
	uint8_t  lap[3];
	uint8_t  length;
	uint8_t  num_resp;
} bt_hci_cmd_periodic_inquiry;

#define BT_HCI_CMD_EXIT_PERIODIC_INQUIRY	0x0404

#define BT_HCI_CMD_CREATE_CONN			0x0405
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint16_t pkt_type;
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_mode;
	uint16_t clock_offset;
	uint8_t  role_switch;
} bt_hci_cmd_create_conn;

#define BT_HCI_CMD_DISCONNECT			0x0406
typedef struct __packed {
	uint16_t handle;
	uint8_t  reason;
} bt_hci_cmd_disconnect;

#define BT_HCI_CMD_ADD_SCO_CONN			0x0407
typedef struct __packed {
	uint16_t handle;
	uint16_t pkt_type;
} bt_hci_cmd_add_sco_conn;

#define BT_HCI_CMD_CREATE_CONN_CANCEL		0x0408
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_create_conn_cancel;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_create_conn_cancel;

#define BT_HCI_CMD_ACCEPT_CONN_REQUEST		0x0409
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  role;
} bt_hci_cmd_accept_conn_request;

#define BT_HCI_CMD_REJECT_CONN_REQUEST		0x040a
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  reason;
} bt_hci_cmd_reject_conn_request;

#define BT_HCI_CMD_LINK_KEY_REQUEST_REPLY	0x040b
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  link_key[16];
} bt_hci_cmd_link_key_request_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_link_key_request_reply;

#define BT_HCI_CMD_LINK_KEY_REQUEST_NEG_REPLY	0x040c
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_link_key_request_neg_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_link_key_request_neg_reply;

#define BT_HCI_CMD_PIN_CODE_REQUEST_REPLY	0x040d
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  pin_len;
	uint8_t  pin_code[16];
} bt_hci_cmd_pin_code_request_reply;

#define BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY	0x040e
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_pin_code_request_neg_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_pin_code_request_neg_reply;

#define BT_HCI_CMD_CHANGE_CONN_PKT_TYPE		0x040f
typedef struct __packed {
	uint16_t handle;
	uint16_t pkt_type;
} bt_hci_cmd_change_conn_pkt_type;

#define BT_HCI_CMD_AUTH_REQUESTED		0x0411
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_auth_requested;

#define BT_HCI_CMD_SET_CONN_ENCRYPT		0x0413
typedef struct __packed {
	uint16_t handle;
	uint8_t  encr_mode;
} bt_hci_cmd_set_conn_encrypt;

#define BT_HCI_CMD_CHANGE_CONN_LINK_KEY		0x0415
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_change_conn_link_key;

#define BT_HCI_CMD_LINK_KEY_SELECTION		0x0417
typedef struct __packed {
	uint8_t  key_flag;
} bt_hci_cmd_link_key_selection;

#define BT_HCI_CMD_REMOTE_NAME_REQUEST		0x0419
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_mode;
	uint16_t clock_offset;
} bt_hci_cmd_remote_name_request;

#define BT_HCI_CMD_REMOTE_NAME_REQUEST_CANCEL	0x041a
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_remote_name_request_cancel;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_remote_name_request_cancel;

#define BT_HCI_CMD_READ_REMOTE_FEATURES		0x041b
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_remote_features;

#define BT_HCI_CMD_READ_REMOTE_EXT_FEATURES	0x041c
typedef struct __packed {
	uint16_t handle;
	uint8_t  page;
} bt_hci_cmd_read_remote_ext_features;

#define BT_HCI_CMD_READ_REMOTE_VERSION		0x041d
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_remote_version;

#define BT_HCI_CMD_READ_CLOCK_OFFSET		0x041f
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_clock_offset;

#define BT_HCI_CMD_READ_LMP_HANDLE		0x0420
typedef struct __packed {
	uint16_t  handle;
} bt_hci_cmd_read_lmp_handle;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  lmp_handle;
	uint32_t reserved;
} bt_hci_rsp_read_lmp_handle;

#define BT_HCI_CMD_SETUP_SYNC_CONN		0x0428
typedef struct __packed {
	uint16_t handle;
	uint32_t tx_bandwidth;
	uint32_t rx_bandwidth;
	uint16_t max_latency;
	uint16_t voice_setting;
	uint8_t  retrans_effort;
	uint16_t pkt_type;
} bt_hci_cmd_setup_sync_conn;

#define BT_HCI_CMD_ACCEPT_SYNC_CONN_REQUEST	0x0429
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint32_t tx_bandwidth;
	uint32_t rx_bandwidth;
	uint16_t max_latency;
	uint16_t voice_setting;
	uint8_t  retrans_effort;
	uint16_t pkt_type;
} bt_hci_cmd_accept_sync_conn_request;

#define BT_HCI_CMD_REJECT_SYNC_CONN_REQUEST	0x042a
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  reason;
} bt_hci_cmd_reject_sync_conn_request;

#define BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY		0x042b
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  capability;
	uint8_t  oob_data;
	uint8_t  authentication;
} bt_hci_cmd_io_capability_request_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_io_capability_request_reply;

#define BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY		0x042c
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_user_confirm_request_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_user_confirm_request_reply;

#define BT_HCI_CMD_USER_CONFIRM_REQUEST_NEG_REPLY	0x042d
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_user_confirm_request_neg_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_user_confirm_request_neg_reply;

#define BT_HCI_CMD_USER_PASSKEY_REQUEST_REPLY		0x042e
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint32_t passkey;
} bt_hci_cmd_user_passkey_request_reply;

#define BT_HCI_CMD_USER_PASSKEY_REQUEST_NEG_REPLY	0x042f
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_user_passkey_request_neg_reply;

#define BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_REPLY	0x0430
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  hash[16];
	uint8_t  randomizer[16];
} bt_hci_cmd_remote_oob_data_request_reply;

#define BT_HCI_CMD_REMOTE_OOB_DATA_REQUEST_NEG_REPLY	0x0433
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_remote_oob_data_request_neg_reply;

#define BT_HCI_CMD_IO_CAPABILITY_REQUEST_NEG_REPLY	0x0434
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  reason;
} bt_hci_cmd_io_capability_request_neg_reply;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_io_capability_request_neg_reply;

#define BT_HCI_CMD_CREATE_PHY_LINK		0x0435
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  key_len;
	uint8_t  key_type;
} bt_hci_cmd_create_phy_link;

#define BT_HCI_CMD_ACCEPT_PHY_LINK		0x0436
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  key_len;
	uint8_t  key_type;
} bt_hci_cmd_accept_phy_link;

#define BT_HCI_CMD_DISCONN_PHY_LINK		0x0437
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  reason;
} bt_hci_cmd_disconn_phy_link;

#define BT_HCI_CMD_CREATE_LOGIC_LINK		0x0438
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  tx_flow_spec[16];
	uint8_t  rx_flow_spec[16];
} bt_hci_cmd_create_logic_link;

#define BT_HCI_CMD_ACCEPT_LOGIC_LINK		0x0439
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  tx_flow_spec[16];
	uint8_t  rx_flow_spec[16];
} bt_hci_cmd_accept_logic_link;

#define BT_HCI_CMD_DISCONN_LOGIC_LINK		0x043a
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_disconn_logic_link;

#define BT_HCI_CMD_LOGIC_LINK_CANCEL		0x043b
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  flow_spec;
} bt_hci_cmd_logic_link_cancel;
typedef struct __packed {
	uint8_t  status;
	uint8_t  phy_handle;
	uint8_t  flow_spec;
} bt_hci_rsp_logic_link_cancel;

#define BT_HCI_CMD_FLOW_SPEC_MODIFY		0x043c
typedef struct __packed {
	uint16_t handle;
	uint8_t  tx_flow_spec[16];
	uint8_t  rx_flow_spec[16];
} bt_hci_cmd_flow_spec_modify;

#define BT_HCI_CMD_ENHANCED_SETUP_SYNC_CONN	0x043d
typedef struct __packed {
	uint16_t handle;
	uint32_t tx_bandwidth;
	uint32_t rx_bandwidth;
	uint8_t  tx_coding_format[5];
	uint8_t  rx_coding_format[5];
	uint16_t tx_codec_frame_size;
	uint16_t rx_codec_frame_size;
	uint32_t input_bandwidth;
	uint32_t output_bandwidth;
	uint8_t  input_coding_format[5];
	uint8_t  output_coding_format[5];
	uint16_t input_coded_data_size;
	uint16_t output_coded_data_size;
	uint8_t  input_pcm_data_format;
	uint8_t  output_pcm_data_format;
	uint8_t  input_pcm_msb_position;
	uint8_t  output_pcm_msb_position;
	uint8_t  input_data_path;
	uint8_t  output_data_path;
	uint8_t  input_unit_size;
	uint8_t  output_unit_size;
	uint16_t max_latency;
	uint16_t pkt_type;
	uint8_t  retrans_effort;
} bt_hci_cmd_enhanced_setup_sync_conn;

#define BT_HCI_CMD_ENHANCED_ACCEPT_SYNC_CONN_REQUEST	0x043e
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint32_t tx_bandwidth;
	uint32_t rx_bandwidth;
	uint8_t  tx_coding_format[5];
	uint8_t  rx_coding_format[5];
	uint16_t tx_codec_frame_size;
	uint16_t rx_codec_frame_size;
	uint32_t input_bandwidth;
	uint32_t output_bandwidth;
	uint8_t  input_coding_format[5];
	uint8_t  output_coding_format[5];
	uint16_t input_coded_data_size;
	uint16_t output_coded_data_size;
	uint8_t  input_pcm_data_format;
	uint8_t  output_pcm_data_format;
	uint8_t  input_pcm_msb_position;
	uint8_t  output_pcm_msb_position;
	uint8_t  input_data_path;
	uint8_t  output_data_path;
	uint8_t  input_unit_size;
	uint8_t  output_unit_size;
	uint16_t max_latency;
	uint16_t pkt_type;
	uint8_t  retrans_effort;
} bt_hci_cmd_enhanced_accept_sync_conn_request;

#define BT_HCI_CMD_TRUNCATED_PAGE		0x043f
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint16_t clock_offset;
} bt_hci_cmd_truncated_page;

#define BT_HCI_CMD_TRUNCATED_PAGE_CANCEL	0x0440
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_cmd_truncated_page_cancel;

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST	0x0441
typedef struct __packed {
	uint8_t  enable;
	uint8_t  lt_addr;
	uint8_t  lpo_allowed;
	uint16_t pkt_type;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t timeout;
} bt_hci_cmd_set_peripheral_broadcast;
typedef struct __packed {
	uint8_t  status;
	uint8_t  lt_addr;
	uint16_t interval;
} bt_hci_rsp_set_peripheral_broadcast;

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_RECEIVE	0x0442
typedef struct __packed {
	uint8_t  enable;
	uint8_t  bdaddr[6];
	uint8_t  lt_addr;
	uint16_t interval;
	uint32_t offset;
	uint32_t instant;
	uint16_t timeout;
	uint8_t  accuracy;
	uint8_t  skip;
	uint16_t pkt_type;
	uint8_t  map[10];
} bt_hci_cmd_set_peripheral_broadcast_receive;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint8_t  lt_addr;
} bt_hci_rsp_set_peripheral_broadcast_receive;

#define BT_HCI_CMD_START_SYNC_TRAIN		0x0443

#define BT_HCI_CMD_RECEIVE_SYNC_TRAIN		0x0444
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint16_t timeout;
	uint16_t window;
	uint16_t interval;
} bt_hci_cmd_receive_sync_train;

#define BT_HCI_CMD_REMOTE_OOB_EXT_DATA_REQUEST_REPLY	0x0445
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  hash192[16];
	uint8_t  randomizer192[16];
	uint8_t  hash256[16];
	uint8_t  randomizer256[16];
} bt_hci_cmd_remote_oob_ext_data_request_reply;

#define BT_HCI_CMD_HOLD_MODE			0x0801
typedef struct __packed {
	uint16_t handle;
	uint16_t max_interval;
	uint16_t min_interval;
} bt_hci_cmd_hold_mode;

#define BT_HCI_CMD_SNIFF_MODE			0x0803
typedef struct __packed {
	uint16_t handle;
	uint16_t max_interval;
	uint16_t min_interval;
	uint16_t attempt;
	uint16_t timeout;
} bt_hci_cmd_sniff_mode;

#define BT_HCI_CMD_EXIT_SNIFF_MODE		0x0804
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_exit_sniff_mode;

#define BT_HCI_CMD_PARK_STATE			0x0805
typedef struct __packed {
	uint16_t handle;
	uint16_t max_interval;
	uint16_t min_interval;
} bt_hci_cmd_park_state;

#define BT_HCI_CMD_EXIT_PARK_STATE		0x0806
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_exit_park_state;

#define BT_HCI_CMD_QOS_SETUP			0x0807
typedef struct __packed {
	uint16_t handle;
	uint8_t  flags;
	uint8_t  service_type;
	uint32_t token_rate;
	uint32_t peak_bandwidth;
	uint32_t latency;
	uint32_t delay_variation;
} bt_hci_cmd_qos_setup;

#define BT_HCI_CMD_ROLE_DISCOVERY		0x0809
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_role_discovery;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  role;
} bt_hci_rsp_role_discovery;

#define BT_HCI_CMD_SWITCH_ROLE			0x080b
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  role;
} bt_hci_cmd_switch_role;

#define BT_HCI_CMD_READ_LINK_POLICY		0x080c
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_link_policy;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t policy;
} bt_hci_rsp_read_link_policy;

#define BT_HCI_CMD_WRITE_LINK_POLICY		0x080d
typedef struct __packed {
	uint16_t handle;
	uint16_t policy;
} bt_hci_cmd_write_link_policy;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_write_link_policy;

#define BT_HCI_CMD_READ_DEFAULT_LINK_POLICY	0x080e
typedef struct __packed {
	uint8_t  status;
	uint16_t policy;
} bt_hci_rsp_read_default_link_policy;

#define BT_HCI_CMD_WRITE_DEFAULT_LINK_POLICY	0x080f
typedef struct __packed {
	uint16_t policy;
} bt_hci_cmd_write_default_link_policy;

#define BT_HCI_CMD_FLOW_SPEC			0x0810
typedef struct __packed {
	uint16_t handle;
	uint8_t  flags;
	uint8_t  direction;
	uint8_t  service_type;
	uint32_t token_rate;
	uint32_t token_bucket_size;
	uint32_t peak_bandwidth;
	uint32_t access_latency;
} bt_hci_cmd_flow_spec;

#define BT_HCI_CMD_SNIFF_SUBRATING		0x0811
typedef struct __packed {
	uint16_t handle;
	uint16_t max_latency;
	uint16_t min_remote_timeout;
	uint16_t min_local_timeout;
} bt_hci_cmd_sniff_subrating;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_sniff_subrating;

#define BT_HCI_CMD_SET_EVENT_MASK		0x0c01
typedef struct __packed {
	uint8_t  mask[8];
} bt_hci_cmd_set_event_mask;

#define BT_HCI_CMD_RESET			0x0c03

#define BT_HCI_CMD_SET_EVENT_FILTER		0x0c05
typedef struct __packed {
	uint8_t  type;
	uint8_t  cond_type;
	uint8_t  cond[0];
} bt_hci_cmd_set_event_filter;

#define BT_HCI_CMD_FLUSH			0x0c08
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_flush;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_flush;

#define BT_HCI_CMD_READ_PIN_TYPE		0x0c09
typedef struct __packed {
	uint8_t  status;
	uint8_t  pin_type;
} bt_hci_rsp_read_pin_type;

#define BT_HCI_CMD_WRITE_PIN_TYPE		0x0c0a
typedef struct __packed {
	uint8_t  pin_type;
} bt_hci_cmd_write_pin_type;

#define BT_HCI_CMD_CREATE_NEW_UNIT_KEY		0x0c0b

#define BT_HCI_CMD_READ_STORED_LINK_KEY		0x0c0d
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  read_all;
} bt_hci_cmd_read_stored_link_key;
typedef struct __packed {
	uint8_t  status;
	uint16_t max_num_keys;
	uint16_t num_keys;
} bt_hci_rsp_read_stored_link_key;

#define BT_HCI_CMD_WRITE_STORED_LINK_KEY	0x0c11
typedef struct __packed {
	uint8_t  num_keys;
} bt_hci_cmd_write_stored_link_key;
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_keys;
} bt_hci_rsp_write_stored_link_key;

#define BT_HCI_CMD_DELETE_STORED_LINK_KEY	0x0c12
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  delete_all;
} bt_hci_cmd_delete_stored_link_key;
typedef struct __packed {
	uint8_t  status;
	uint16_t num_keys;
} bt_hci_rsp_delete_stored_link_key;

#define BT_HCI_CMD_WRITE_LOCAL_NAME		0x0c13
typedef struct __packed {
	uint8_t  name[248];
} bt_hci_cmd_write_local_name;

#define BT_HCI_CMD_READ_LOCAL_NAME		0x0c14
typedef struct __packed {
	uint8_t  status;
	uint8_t  name[248];
} bt_hci_rsp_read_local_name;

#define BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT	0x0c15
typedef struct __packed {
	uint8_t  status;
	uint16_t timeout;
} bt_hci_rsp_read_conn_accept_timeout;

#define BT_HCI_CMD_WRITE_CONN_ACCEPT_TIMEOUT	0x0c16
typedef struct __packed {
	uint16_t timeout;
} bt_hci_cmd_write_conn_accept_timeout;

#define BT_HCI_CMD_READ_PAGE_TIMEOUT		0x0c17
typedef struct __packed {
	uint8_t  status;
	uint16_t timeout;
} bt_hci_rsp_read_page_timeout;

#define BT_HCI_CMD_WRITE_PAGE_TIMEOUT		0x0c18
typedef struct __packed {
	uint16_t timeout;
} bt_hci_cmd_write_page_timeout;

#define BT_HCI_CMD_READ_SCAN_ENABLE		0x0c19
typedef struct __packed {
	uint8_t  status;
	uint8_t  enable;
} bt_hci_rsp_read_scan_enable;

#define BT_HCI_CMD_WRITE_SCAN_ENABLE		0x0c1a
typedef struct __packed {
	uint8_t  enable;
} bt_hci_cmd_write_scan_enable;

#define BT_HCI_CMD_READ_PAGE_SCAN_ACTIVITY	0x0c1b
typedef struct __packed {
	uint8_t  status;
	uint16_t interval;
	uint16_t window;
} bt_hci_rsp_read_page_scan_activity;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY	0x0c1c
typedef struct __packed {
	uint16_t interval;
	uint16_t window;
} bt_hci_cmd_write_page_scan_activity;

#define BT_HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY	0x0c1d
typedef struct __packed {
	uint8_t  status;
	uint16_t interval;
	uint16_t window;
} bt_hci_rsp_read_inquiry_scan_activity;

#define BT_HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY	0x0c1e
typedef struct __packed {
	uint16_t interval;
	uint16_t window;
} bt_hci_cmd_write_inquiry_scan_activity;

#define BT_HCI_CMD_READ_AUTH_ENABLE		0x0c1f
typedef struct __packed {
	uint8_t  status;
	uint8_t  enable;
} bt_hci_rsp_read_auth_enable;

#define BT_HCI_CMD_WRITE_AUTH_ENABLE		0x0c20
typedef struct __packed {
	uint8_t  enable;
} bt_hci_cmd_write_auth_enable;

#define BT_HCI_CMD_READ_ENCRYPT_MODE		0x0c21
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_encrypt_mode;

#define BT_HCI_CMD_WRITE_ENCRYPT_MODE		0x0c22
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_encrypt_mode;

#define BT_HCI_CMD_READ_CLASS_OF_DEV		0x0c23
typedef struct __packed {
	uint8_t  status;
	uint8_t  dev_class[3];
} bt_hci_rsp_read_class_of_dev;

#define BT_HCI_CMD_WRITE_CLASS_OF_DEV		0x0c24
typedef struct __packed {
	uint8_t  dev_class[3];
} bt_hci_cmd_write_class_of_dev;

#define BT_HCI_CMD_READ_VOICE_SETTING		0x0c25
typedef struct __packed {
	uint8_t  status;
	uint16_t setting;
} bt_hci_rsp_read_voice_setting;

#define BT_HCI_CMD_WRITE_VOICE_SETTING		0x0c26
typedef struct __packed {
	uint16_t setting;
} bt_hci_cmd_write_voice_setting;

#define BT_HCI_CMD_READ_AUTO_FLUSH_TIMEOUT	0x0c27
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_auto_flush_timeout;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t timeout;
} bt_hci_rsp_read_auto_flush_timeout;

#define BT_HCI_CMD_WRITE_AUTO_FLUSH_TIMEOUT	0x0c28
typedef struct __packed {
	uint16_t handle;
	uint16_t timeout;
} bt_hci_cmd_write_auto_flush_timeout;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_write_auto_flush_timeout;

#define BT_HCI_CMD_READ_NUM_BROADCAST_RETRANS	0x0c29
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_retrans;
} bt_hci_rsp_read_num_broadcast_retrans;

#define BT_HCI_CMD_WRITE_NUM_BROADCAST_RETRANS	0x0c2a
typedef struct __packed {
	uint8_t  num_retrans;
} bt_hci_cmd_write_num_broadcast_retrans;

#define BT_HCI_CMD_READ_HOLD_MODE_ACTIVITY	0x0c2b
typedef struct __packed {
	uint8_t  status;
	uint8_t  activity;
} bt_hci_rsp_read_hold_mode_activity;

#define BT_HCI_CMD_WRITE_HOLD_MODE_ACTIVITY	0x0c2c
typedef struct __packed {
	uint8_t  activity;
} bt_hci_cmd_write_hold_mode_activity;

#define BT_HCI_CMD_READ_TX_POWER		0x0c2d
typedef struct __packed {
	uint16_t handle;
	uint8_t  type;
} bt_hci_cmd_read_tx_power;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	int8_t   level;
} bt_hci_rsp_read_tx_power;

#define BT_HCI_CMD_READ_SYNC_FLOW_CONTROL	0x0c2e
typedef struct __packed {
	uint8_t  status;
	uint8_t  enable;
} bt_hci_rsp_read_sync_flow_control;

#define BT_HCI_CMD_WRITE_SYNC_FLOW_CONTROL	0x0c2f
typedef struct __packed {
	uint8_t  enable;
} bt_hci_cmd_write_sync_flow_control;

#define BT_HCI_CMD_SET_HOST_FLOW_CONTROL	0x0c31
typedef struct __packed {
	uint8_t  enable;
} bt_hci_cmd_set_host_flow_control;

#define BT_HCI_CMD_HOST_BUFFER_SIZE		0x0c33
typedef struct __packed {
	uint16_t acl_mtu;
	uint8_t  sco_mtu;
	uint16_t acl_max_pkt;
	uint16_t sco_max_pkt;
} bt_hci_cmd_host_buffer_size;

#define BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS	0x0c35
typedef struct __packed {
	uint8_t  num_handles;
	uint16_t handle;
	uint16_t count;
} bt_hci_cmd_host_num_completed_packets;

#define BT_HCI_CMD_READ_LINK_SUPV_TIMEOUT	0x0c36
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_link_supv_timeout;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t timeout;
} bt_hci_rsp_read_link_supv_timeout;

#define BT_HCI_CMD_WRITE_LINK_SUPV_TIMEOUT	0x0c37
typedef struct __packed {
	uint16_t handle;
	uint16_t timeout;
} bt_hci_cmd_write_link_supv_timeout;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_write_link_supv_timeout;

#define BT_HCI_CMD_READ_NUM_SUPPORTED_IAC	0x0c38
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_iac;
} bt_hci_rsp_read_num_supported_iac;

#define BT_HCI_CMD_READ_CURRENT_IAC_LAP		0x0c39
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_iac;
	uint8_t  iac_lap[0];
} bt_hci_rsp_read_current_iac_lap;

#define BT_HCI_CMD_WRITE_CURRENT_IAC_LAP	0x0c3a
typedef struct __packed {
	uint8_t  num_iac;
	uint8_t  iac_lap[0];
} bt_hci_cmd_write_current_iac_lap;

#define BT_HCI_CMD_READ_PAGE_SCAN_PERIOD_MODE	0x0c3b
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_page_scan_period_mode;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_PERIOD_MODE	0x0c3c
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_page_scan_period_mode;

#define BT_HCI_CMD_READ_PAGE_SCAN_MODE		0x0c3d
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_page_scan_mode;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_MODE		0x0c3e
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_page_scan_mode;

#define BT_HCI_CMD_SET_AFH_HOST_CLASSIFICATION	0x0c3f
typedef struct __packed {
	uint8_t  map[10];
} bt_hci_cmd_set_afh_host_classification;

#define BT_HCI_CMD_READ_INQUIRY_SCAN_TYPE	0x0c42
typedef struct __packed {
	uint8_t  status;
	uint8_t  type;
} bt_hci_rsp_read_inquiry_scan_type;

#define BT_HCI_CMD_WRITE_INQUIRY_SCAN_TYPE	0x0c43
typedef struct __packed {
	uint8_t type;
} bt_hci_cmd_write_inquiry_scan_type;

#define BT_HCI_CMD_READ_INQUIRY_MODE		0x0c44
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_inquiry_mode;

#define BT_HCI_CMD_WRITE_INQUIRY_MODE		0x0c45
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_inquiry_mode;

#define BT_HCI_CMD_READ_PAGE_SCAN_TYPE		0x0c46
typedef struct __packed {
	uint8_t status;
	uint8_t type;
} bt_hci_rsp_read_page_scan_type;

#define BT_HCI_CMD_WRITE_PAGE_SCAN_TYPE		0x0c47
typedef struct __packed {
	uint8_t type;
} bt_hci_cmd_write_page_scan_type;

#define BT_HCI_CMD_READ_AFH_ASSESSMENT_MODE	0x0c48
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_afh_assessment_mode;

#define BT_HCI_CMD_WRITE_AFH_ASSESSMENT_MODE	0x0c49
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_afh_assessment_mode;

#define BT_HCI_CMD_READ_EXT_INQUIRY_RESPONSE	0x0c51
typedef struct __packed {
	uint8_t  status;
	uint8_t  fec;
	uint8_t  data[240];
} bt_hci_rsp_read_ext_inquiry_response;

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE	0x0c52
typedef struct __packed {
	uint8_t  fec;
	uint8_t  data[240];
} bt_hci_cmd_write_ext_inquiry_response;

#define BT_HCI_CMD_REFRESH_ENCRYPT_KEY		0x0c53
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_refresh_encrypt_key;

#define BT_HCI_CMD_READ_SIMPLE_PAIRING_MODE	0x0c55
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_simple_pairing_mode;

#define BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE	0x0c56
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_simple_pairing_mode;

#define BT_HCI_CMD_READ_LOCAL_OOB_DATA		0x0c57
typedef struct __packed {
	uint8_t  status;
	uint8_t  hash[16];
	uint8_t  randomizer[16];
} bt_hci_rsp_read_local_oob_data;

#define BT_HCI_CMD_READ_INQUIRY_RESP_TX_POWER	0x0c58
typedef struct __packed {
	uint8_t  status;
	int8_t   level;
} bt_hci_rsp_read_inquiry_resp_tx_power;

#define BT_HCI_CMD_WRITE_INQUIRY_TX_POWER	0x0c59
typedef struct __packed {
	int8_t   level;
} bt_hci_cmd_write_inquiry_tx_power;

#define BT_HCI_CMD_READ_ERRONEOUS_REPORTING	0x0c5a
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_erroneous_reporting;

#define BT_HCI_CMD_WRITE_ERRONEOUS_REPORTING	0x0c5b
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_erroneous_reporting;

#define BT_HCI_CMD_ENHANCED_FLUSH		0x0c5f
typedef struct __packed {
	uint16_t handle;
	uint8_t  type;
} bt_hci_cmd_enhanced_flush;

#define BT_HCI_CMD_SEND_KEYPRESS_NOTIFY		0x0c60
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  type;
} bt_hci_cmd_send_keypress_notify;
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_send_keypress_notify;

#define BT_HCI_CMD_SET_EVENT_MASK_PAGE2		0x0c63
typedef struct __packed {
	uint8_t  mask[8];
} bt_hci_cmd_set_event_mask_page2;

#define BT_HCI_CMD_READ_LOCATION_DATA		0x0c64
typedef struct __packed {
	uint8_t  status;
	uint8_t  domain_aware;
	uint8_t  domain[2];
	uint8_t  domain_options;
	uint8_t  options;
} bt_hci_rsp_read_location_data;

#define BT_HCI_CMD_WRITE_LOCATION_DATA		0x0c65
typedef struct __packed {
	uint8_t  domain_aware;
	uint8_t  domain[2];
	uint8_t  domain_options;
	uint8_t  options;
} bt_hci_cmd_write_location_data;

#define BT_HCI_CMD_READ_FLOW_CONTROL_MODE	0x0c66
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_flow_control_mode;

#define BT_HCI_CMD_WRITE_FLOW_CONTROL_MODE	0x0c67
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_flow_control_mode;

#define BT_HCI_CMD_READ_ENHANCED_TX_POWER	0x0c68
typedef struct __packed {
	uint16_t handle;
	uint8_t  type;
} bt_hci_cmd_read_enhanced_tx_power;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	int8_t   level_gfsk;
	int8_t   level_dqpsk;
	int8_t   level_8dpsk;
} bt_hci_rsp_read_enhanced_tx_power;

#define BT_HCI_CMD_SHORT_RANGE_MODE		0x0c6b
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  mode;
} bt_hci_cmd_short_range_mode;

#define BT_HCI_CMD_READ_LE_HOST_SUPPORTED	0x0c6c
typedef struct __packed {
	uint8_t  status;
	uint8_t  supported;
	uint8_t  simultaneous;
} bt_hci_rsp_read_le_host_supported;

#define BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED	0x0c6d
typedef struct __packed {
	uint8_t  supported;
	uint8_t  simultaneous;
} bt_hci_cmd_write_le_host_supported;

#define BT_HCI_CMD_SET_RESERVED_LT_ADDR		0x0c74
typedef struct __packed {
	uint8_t  lt_addr;
} bt_hci_cmd_set_reserved_lt_addr;
typedef struct __packed {
	uint8_t  status;
	uint8_t  lt_addr;
} bt_hci_rsp_set_reserved_lt_addr;

#define BT_HCI_CMD_DELETE_RESERVED_LT_ADDR	0x0c75
typedef struct __packed {
	uint8_t  lt_addr;
} bt_hci_cmd_delete_reserved_lt_addr;
typedef struct __packed {
	uint8_t  status;
	uint8_t  lt_addr;
} bt_hci_rsp_delete_reserved_lt_addr;

#define BT_HCI_CMD_SET_PERIPHERAL_BROADCAST_DATA	0x0c76
typedef struct __packed {
	uint8_t  lt_addr;
	uint8_t  fragment;
	uint8_t  length;
} bt_hci_cmd_set_peripheral_broadcast_data;
typedef struct __packed {
	uint8_t  status;
	uint8_t  lt_addr;
} bt_hci_rsp_set_peripheral_broadcast_data;

#define BT_HCI_CMD_READ_SYNC_TRAIN_PARAMS	0x0c77
typedef struct __packed {
	uint8_t  status;
	uint16_t interval;
	uint32_t timeout;
	uint8_t  service_data;
} bt_hci_rsp_read_sync_train_params;

#define BT_HCI_CMD_WRITE_SYNC_TRAIN_PARAMS	0x0c78
typedef struct __packed {
	uint16_t min_interval;
	uint16_t max_interval;
	uint32_t timeout;
	uint8_t  service_data;
} bt_hci_cmd_write_sync_train_params;
typedef struct __packed {
	uint8_t  status;
	uint16_t interval;
} bt_hci_rsp_write_sync_train_params;

#define BT_HCI_CMD_READ_SECURE_CONN_SUPPORT	0x0c79
typedef struct __packed {
	uint8_t  status;
	uint8_t  support;
} bt_hci_rsp_read_secure_conn_support;

#define BT_HCI_CMD_WRITE_SECURE_CONN_SUPPORT	0x0c7a
typedef struct __packed {
	uint8_t support;
} bt_hci_cmd_write_secure_conn_support;

#define BT_HCI_CMD_READ_AUTH_PAYLOAD_TIMEOUT	0x0c7b
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_auth_payload_timeout;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t timeout;
} bt_hci_rsp_read_auth_payload_timeout;

#define BT_HCI_CMD_WRITE_AUTH_PAYLOAD_TIMEOUT	0x0c7c
typedef struct __packed {
	uint16_t handle;
	uint16_t timeout;
} bt_hci_cmd_write_auth_payload_timeout;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_write_auth_payload_timeout;

#define BT_HCI_CMD_READ_LOCAL_OOB_EXT_DATA	0x0c7d
typedef struct __packed {
	uint8_t  status;
	uint8_t  hash192[16];
	uint8_t  randomizer192[16];
	uint8_t  hash256[16];
	uint8_t  randomizer256[16];
} bt_hci_rsp_read_local_oob_ext_data;

#define BT_HCI_CMD_READ_EXT_PAGE_TIMEOUT	0x0c7e
typedef struct __packed {
	uint8_t  status;
	uint16_t timeout;
} bt_hci_rsp_read_ext_page_timeout;

#define BT_HCI_CMD_WRITE_EXT_PAGE_TIMEOUT	0x0c7f
typedef struct __packed {
	uint16_t timeout;
} bt_hci_cmd_write_ext_page_timeout;

#define BT_HCI_CMD_READ_EXT_INQUIRY_LENGTH	0x0c80
typedef struct __packed {
	uint8_t  status;
	uint16_t interval;
} bt_hci_rsp_read_ext_inquiry_length;

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_LENGTH	0x0c81
typedef struct __packed {
	uint16_t interval;
} bt_hci_cmd_write_ext_inquiry_length;

#define BT_HCI_CMD_CONFIG_DATA_PATH		0x0c83
#define BT_HCI_BIT_CONFIG_DATA_PATH		BT_HCI_CMD_BIT(45, 5)
typedef struct __packed {
	uint8_t  dir;
	uint8_t  id;
	uint8_t  vnd_config_len;
	uint8_t  vnd_config[0];
} bt_hci_cmd_config_data_path;

#define BT_HCI_CMD_SET_MIN_ENC_KEY_SIZE		0x0c84
typedef struct __packed {
	uint8_t min_size;
} bt_hci_cmd_set_min_enc_key_size;

#define BT_HCI_CMD_READ_LOCAL_VERSION		0x1001
typedef struct __packed {
	uint8_t  status;
	uint8_t  hci_ver;
	uint16_t hci_rev;
	uint8_t  lmp_ver;
	uint16_t manufacturer;
	uint16_t lmp_subver;
} bt_hci_rsp_read_local_version;

#define BT_HCI_CMD_READ_LOCAL_COMMANDS		0x1002
typedef struct __packed {
	uint8_t  status;
	uint8_t  commands[64];
} bt_hci_rsp_read_local_commands;

#define BT_HCI_CMD_READ_LOCAL_FEATURES		0x1003
typedef struct __packed {
	uint8_t  status;
	uint8_t  features[8];
} bt_hci_rsp_read_local_features;

#define BT_HCI_CMD_READ_LOCAL_EXT_FEATURES	0x1004
typedef struct __packed {
	uint8_t  page;
} bt_hci_cmd_read_local_ext_features;
typedef struct __packed {
	uint8_t  status;
	uint8_t  page;
	uint8_t  max_page;
	uint8_t  features[8];
} bt_hci_rsp_read_local_ext_features;

#define BT_HCI_CMD_READ_BUFFER_SIZE		0x1005
typedef struct __packed {
	uint8_t  status;
	uint16_t acl_mtu;
	uint8_t  sco_mtu;
	uint16_t acl_max_pkt;
	uint16_t sco_max_pkt;
} bt_hci_rsp_read_buffer_size;

#define BT_HCI_CMD_READ_COUNTRY_CODE		0x1007
typedef struct __packed {
	uint8_t  status;
	uint8_t  code;
} bt_hci_rsp_read_country_code;

#define BT_HCI_CMD_READ_BD_ADDR			0x1009
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_rsp_read_bd_addr;

#define BT_HCI_CMD_READ_DATA_BLOCK_SIZE		0x100a
typedef struct __packed {
	uint8_t  status;
	uint16_t max_acl_len;
	uint16_t block_len;
	uint16_t num_blocks;
} bt_hci_rsp_read_data_block_size;

#define BT_HCI_CMD_READ_LOCAL_CODECS		0x100b
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_codecs;
	uint8_t  codec[0];
} bt_hci_rsp_read_local_codecs;

#define BT_HCI_CMD_READ_LOCAL_PAIRING_OPTIONS	0x100c
typedef struct __packed {
	uint8_t  status;
	uint8_t  pairing_options;
	uint8_t  max_key_size;
} bt_hci_rsp_read_local_pairing_options;

#define BT_HCI_CMD_READ_LOCAL_CODECS_V2		0x100d
#define BT_HCI_BIT_READ_LOCAL_CODECS_V2		BT_HCI_CMD_BIT(45, 2)
#define BT_HCI_LOCAL_CODEC_BREDR_ACL		BIT(0)
#define BT_HCI_LOCAL_CODEC_BREDR_SCO		BIT(1)
#define BT_HCI_LOCAL_CODEC_LE_CIS		BIT(2)
#define BT_HCI_LOCAL_CODEC_LE_BIS		BIT(3)

typedef struct __packed {
	uint16_t cid;
	uint16_t vid;
	uint8_t  transport;
} bt_hci_vnd_codec_v2;

typedef struct __packed {
	uint8_t  id;
	uint16_t cid;
	uint16_t vid;
	uint8_t  transport;
} bt_hci_vnd_codec;

typedef struct __packed {
	uint8_t  id;
	uint8_t  transport;
} bt_hci_codec;

typedef struct __packed {
	uint8_t  status;
	uint8_t  num_codecs;
	bt_hci_codec codec[0];
} bt_hci_rsp_read_local_codecs_v2;

#define BT_HCI_CMD_READ_LOCAL_CODEC_CAPS	0x100e
#define BT_HCI_BIT_READ_LOCAL_CODEC_CAPS	BT_HCI_CMD_BIT(45, 3)
typedef struct __packed {
	bt_hci_vnd_codec codec;
	uint8_t  dir;
} bt_hci_cmd_read_local_codec_caps;

typedef struct __packed {
	uint8_t  len;
	uint8_t  data[0];
} bt_hci_codec_caps;

typedef struct __packed {
	uint8_t  status;
	uint8_t  num;
	bt_hci_codec_caps caps[0];
} bt_hci_rsp_read_local_codec_caps;

#define BT_HCI_CMD_READ_LOCAL_CTRL_DELAY	0x100f
#define BT_HCI_BIT_READ_LOCAL_CTRL_DELAY	BT_HCI_CMD_BIT(45, 4)
typedef struct __packed {
	bt_hci_vnd_codec codec;
	uint8_t  dir;
	uint8_t  codec_cfg_len;
	uint8_t  codec_cfg[0];
} bt_hci_cmd_read_local_ctrl_delay;

typedef struct __packed {
	uint8_t  status;
	uint8_t  min_delay[3];
	uint8_t  max_delay[3];
} bt_hci_rsp_read_local_ctrl_delay;

#define BT_HCI_CMD_READ_FAILED_CONTACT_COUNTER	0x1401
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_failed_contact_counter;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t counter;
} bt_hci_rsp_read_failed_contact_counter;

#define BT_HCI_CMD_RESET_FAILED_CONTACT_COUNTER	0x1402
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_reset_failed_contact_counter;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_reset_failed_contact_counter;

#define BT_HCI_CMD_READ_LINK_QUALITY		0x1403
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_link_quality;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  link_quality;
} bt_hci_rsp_read_link_quality;

#define BT_HCI_CMD_READ_RSSI			0x1405
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_rssi;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	int8_t   rssi;
} bt_hci_rsp_read_rssi;

#define BT_HCI_CMD_READ_AFH_CHANNEL_MAP		0x1406
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_afh_channel_map;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  mode;
	uint8_t  map[10];
} bt_hci_rsp_read_afh_channel_map;

#define BT_HCI_CMD_READ_CLOCK			0x1407
typedef struct __packed {
	uint16_t handle;
	uint8_t  type;
} bt_hci_cmd_read_clock;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint32_t clock;
	uint16_t accuracy;
} bt_hci_rsp_read_clock;

#define BT_HCI_CMD_READ_ENCRYPT_KEY_SIZE	0x1408
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_read_encrypt_key_size;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  key_size;
} bt_hci_rsp_read_encrypt_key_size;

#define BT_HCI_CMD_READ_LOCAL_AMP_INFO		0x1409
typedef struct __packed {
	uint8_t  status;
	uint8_t  amp_status;
	uint32_t total_bw;
	uint32_t max_bw;
	uint32_t min_latency;
	uint32_t max_pdu;
	uint8_t  amp_type;
	uint16_t pal_cap;
	uint16_t max_assoc_len;
	uint32_t max_flush_to;
	uint32_t be_flush_to;
} bt_hci_rsp_read_local_amp_info;

#define BT_HCI_CMD_READ_LOCAL_AMP_ASSOC		0x140a
typedef struct __packed {
	uint8_t  phy_handle;
	uint16_t len_so_far;
	uint16_t max_assoc_len;
} bt_hci_cmd_read_local_amp_assoc;
typedef struct __packed {
	uint8_t  status;
	uint8_t  phy_handle;
	uint16_t remain_assoc_len;
	uint8_t  assoc_fragment[248];
} bt_hci_rsp_read_local_amp_assoc;

#define BT_HCI_CMD_WRITE_REMOTE_AMP_ASSOC	0x140b
typedef struct __packed {
	uint8_t  phy_handle;
	uint16_t len_so_far;
	uint16_t remain_assoc_len;
	uint8_t  assoc_fragment[248];
} bt_hci_cmd_write_remote_amp_assoc;
typedef struct __packed {
	uint8_t  status;
	uint8_t  phy_handle;
} bt_hci_rsp_write_remote_amp_assoc;

#define BT_HCI_CMD_GET_MWS_TRANSPORT_CONFIG	0x140c
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_transports;
	uint8_t  transport[0];
} bt_hci_rsp_get_mws_transport_config;

#define BT_HCI_CMD_SET_TRIGGERED_CLOCK_CAPTURE	0x140d
typedef struct __packed {
	uint16_t handle;
	uint8_t  enable;
	uint8_t  type;
	uint8_t  lpo_allowed;
	uint8_t  num_filter;
} bt_hci_cmd_set_triggered_clock_capture;

#define BT_HCI_CMD_READ_LOOPBACK_MODE		0x1801
typedef struct __packed {
	uint8_t  status;
	uint8_t  mode;
} bt_hci_rsp_read_loopback_mode;

#define BT_HCI_CMD_WRITE_LOOPBACK_MODE		0x1802
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_loopback_mode;

#define BT_HCI_CMD_ENABLE_DUT_MODE		0x1803

#define BT_HCI_CMD_WRITE_SSP_DEBUG_MODE		0x1804
typedef struct __packed {
	uint8_t  mode;
} bt_hci_cmd_write_ssp_debug_mode;

#define BT_HCI_CMD_LE_SET_EVENT_MASK		0x2001
typedef struct __packed {
	uint8_t  mask[8];
} bt_hci_cmd_le_set_event_mask;

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE		0x2002
typedef struct __packed {
	uint8_t  status;
    uint16_t le_mtu;
    uint8_t  le_max_pkt;
} bt_hci_rsp_le_read_buffer_size;

#define BT_HCI_CMD_LE_READ_LOCAL_FEATURES	0x2003
typedef struct __packed {
	uint8_t  status;
	uint8_t  features[8];
} bt_hci_rsp_le_read_local_features;

#define BT_HCI_CMD_LE_SET_RANDOM_ADDRESS	0x2005
typedef struct __packed {
	uint8_t  addr[6];
} bt_hci_cmd_le_set_random_address;

#define BT_HCI_CMD_LE_SET_ADV_PARAMETERS	0x2006
typedef struct __packed {
	uint16_t min_interval;
	uint16_t max_interval;
	uint8_t  type;
	uint8_t  own_addr_type;
	uint8_t  direct_addr_type;
	uint8_t  direct_addr[6];
	uint8_t  channel_map;
	uint8_t  filter_policy;
} bt_hci_cmd_le_set_adv_parameters;

#define BT_HCI_CMD_LE_READ_ADV_TX_POWER		0x2007
typedef struct __packed {
	uint8_t  status;
	int8_t   level;
} bt_hci_rsp_le_read_adv_tx_power;

#define BT_HCI_CMD_LE_SET_ADV_DATA		0x2008
typedef struct __packed {
	uint8_t  len;
	uint8_t  data[31];
} bt_hci_cmd_le_set_adv_data;

#define BT_HCI_CMD_LE_SET_SCAN_RSP_DATA		0x2009
typedef struct __packed {
	uint8_t  len;
	uint8_t  data[31];
} bt_hci_cmd_le_set_scan_rsp_data;

#define BT_HCI_CMD_LE_SET_ADV_ENABLE		0x200a
typedef struct __packed {
	uint8_t  enable;
} bt_hci_cmd_le_set_adv_enable;

#define BT_HCI_CMD_LE_SET_SCAN_PARAMETERS	0x200b
typedef struct __packed {
	uint8_t  type;
	uint16_t interval;
	uint16_t window;
	uint8_t  own_addr_type;
	uint8_t  filter_policy;
} bt_hci_cmd_le_set_scan_parameters;

#define BT_HCI_CMD_LE_SET_SCAN_ENABLE		0x200c
typedef struct __packed {
	uint8_t  enable;
	uint8_t  filter_dup;
} bt_hci_cmd_le_set_scan_enable;

#define BT_HCI_CMD_LE_CREATE_CONN		0x200d
typedef struct __packed {
	uint16_t scan_interval;
	uint16_t scan_window;
	uint8_t  filter_policy;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint8_t  own_addr_type;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t supv_timeout;
	uint16_t min_length;
	uint16_t max_length;
} bt_hci_cmd_le_create_conn;

#define BT_HCI_CMD_LE_CREATE_CONN_CANCEL		0x200e

#define BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE		0x200f
typedef struct __packed {
	uint8_t  status;
	uint8_t  size;
} bt_hci_rsp_le_read_accept_list_size;

#define BT_HCI_CMD_LE_CLEAR_ACCEPT_LIST			0x2010

#define BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST		0x2011
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
} bt_hci_cmd_le_add_to_accept_list;

#define BT_HCI_CMD_LE_REMOVE_FROM_ACCEPT_LIST	0x2012
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
} bt_hci_cmd_le_remove_from_accept_list;

#define BT_HCI_CMD_LE_CONN_UPDATE				0x2013
typedef struct __packed {
	uint16_t handle;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t supv_timeout;
	uint16_t min_length;
	uint16_t max_length;
} bt_hci_cmd_le_conn_update;

#define BT_HCI_CMD_LE_SET_HOST_CLASSIFICATION	0x2014
typedef struct __packed {
	uint8_t  map[5];
} bt_hci_cmd_le_set_host_classification;

#define BT_HCI_CMD_LE_READ_CHANNEL_MAP			0x2015
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_read_channel_map;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  map[5];
} bt_hci_rsp_le_read_channel_map;

#define BT_HCI_CMD_LE_READ_REMOTE_FEATURES		0x2016
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_read_remote_features;

#define BT_HCI_CMD_LE_ENCRYPT					0x2017
typedef struct __packed {
	uint8_t  key[16];
	uint8_t  plaintext[16];
} bt_hci_cmd_le_encrypt;
typedef struct __packed {
	uint8_t  status;
	uint8_t  data[16];
} bt_hci_rsp_le_encrypt;

#define BT_HCI_CMD_LE_RAND						0x2018
typedef struct __packed {
	uint8_t  status;
	uint64_t number;
} bt_hci_rsp_le_rand;

#define BT_HCI_CMD_LE_START_ENCRYPT				0x2019
typedef struct __packed {
	uint16_t handle;
	uint64_t rand;
	uint16_t ediv;
	uint8_t  ltk[16];
} bt_hci_cmd_le_start_encrypt;

#define BT_HCI_CMD_LE_LTK_REQ_REPLY				0x201a
typedef struct __packed {
	uint16_t handle;
	uint8_t  ltk[16];
} bt_hci_cmd_le_ltk_req_reply;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_ltk_req_reply;

#define BT_HCI_CMD_LE_LTK_REQ_NEG_REPLY			0x201b
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_ltk_req_neg_reply;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_ltk_req_neg_reply;

#define BT_HCI_CMD_LE_READ_SUPPORTED_STATES		0x201c
typedef struct __packed {
	uint8_t  status;
	uint8_t  states[8];
} bt_hci_rsp_le_read_supported_states;

#define BT_HCI_CMD_LE_RECEIVER_TEST				0x201d
typedef struct __packed {
	uint8_t  frequency;
} bt_hci_cmd_le_receiver_test;

#define BT_HCI_CMD_LE_TRANSMITTER_TEST			0x201e
typedef struct __packed {
	uint8_t  frequency;
	uint8_t  data_len;
	uint8_t  payload;
} bt_hci_cmd_le_transmitter_test;

#define BT_HCI_CMD_LE_TEST_END					0x201f
typedef struct __packed {
	uint8_t  status;
	uint16_t num_packets;
} bt_hci_rsp_le_test_end;

#define BT_HCI_CMD_LE_CONN_PARAM_REQ_REPLY		0x2020
typedef struct __packed {
	uint16_t handle;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t supv_timeout;
	uint16_t min_length;
	uint16_t max_length;
} bt_hci_cmd_le_conn_param_req_reply;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_conn_param_req_reply;

#define BT_HCI_CMD_LE_CONN_PARAM_REQ_NEG_REPLY	0x2021
typedef struct __packed {
	uint16_t handle;
	uint8_t  reason;
} bt_hci_cmd_le_conn_param_req_neg_reply;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_conn_param_req_neg_reply;

#define BT_HCI_CMD_LE_SET_DATA_LENGTH			0x2022
typedef struct __packed {
	uint16_t handle;
	uint16_t tx_len;
	uint16_t tx_time;
} bt_hci_cmd_le_set_data_length;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_set_data_length;

#define BT_HCI_CMD_LE_READ_DEFAULT_DATA_LENGTH	0x2023
typedef struct __packed {
	uint8_t  status;
	uint16_t tx_len;
	uint16_t tx_time;
} bt_hci_rsp_le_read_default_data_length;

#define BT_HCI_CMD_LE_WRITE_DEFAULT_DATA_LENGTH	0x2024
typedef struct __packed {
	uint16_t tx_len;
	uint16_t tx_time;
} bt_hci_cmd_le_write_default_data_length;

#define BT_HCI_CMD_LE_READ_LOCAL_PK256			0x2025

#define BT_HCI_CMD_LE_GENERATE_DHKEY			0x2026
typedef struct __packed {
	uint8_t  remote_pk256[64];
} bt_hci_cmd_le_generate_dhkey;

#define BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST		0x2027
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  peer_irk[16];
	uint8_t  local_irk[16];
} bt_hci_cmd_le_add_to_resolv_list;

#define BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST	0x2028
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
} bt_hci_cmd_le_remove_from_resolv_list;

#define BT_HCI_CMD_LE_CLEAR_RESOLV_LIST			0x2029

#define BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE		0x202a
typedef struct __packed {
	uint8_t  status;
	uint8_t  size;
} bt_hci_rsp_le_read_resolv_list_size;

#define BT_HCI_CMD_LE_READ_PEER_RESOLV_ADDR		0x202b
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
} bt_hci_cmd_le_read_peer_resolv_addr;
typedef struct __packed {
	uint8_t  status;
	uint8_t  addr[6];
} bt_hci_rsp_le_read_peer_resolv_addr;

#define BT_HCI_CMD_LE_READ_LOCAL_RESOLV_ADDR	0x202c
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
} bt_hci_cmd_le_read_local_resolv_addr;
typedef struct __packed {
	uint8_t  status;
	uint8_t  addr[6];
} bt_hci_rsp_le_read_local_resolv_addr;

#define BT_HCI_CMD_LE_SET_RESOLV_ENABLE			0x202d
typedef struct __packed {
	uint8_t  enable;
} bt_hci_cmd_le_set_resolv_enable;

#define BT_HCI_CMD_LE_SET_RESOLV_TIMEOUT		0x202e
typedef struct __packed {
	uint16_t timeout;
} bt_hci_cmd_le_set_resolv_timeout;

#define BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH	0x202f
typedef struct __packed {
	uint8_t  status;
	uint16_t max_tx_len;
	uint16_t max_tx_time;
	uint16_t max_rx_len;
	uint16_t max_rx_time;
} bt_hci_rsp_le_read_max_data_length;

#define BT_HCI_CMD_LE_READ_PHY			0x2030
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_read_phy;
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  tx_phy;
	uint8_t  rx_phy;
} bt_hci_rsp_le_read_phy;

#define BT_HCI_CMD_LE_SET_DEFAULT_PHY		0x2031
typedef struct __packed {
	uint8_t  all_phys;
	uint8_t  tx_phys;
	uint8_t  rx_phys;
} bt_hci_cmd_le_set_default_phy;

#define BT_HCI_CMD_LE_SET_PHY			0x2032
typedef struct __packed {
	uint16_t handle;
	uint8_t  all_phys;
	uint8_t  tx_phys;
	uint8_t  rx_phys;
	uint16_t phy_opts;
} bt_hci_cmd_le_set_phy;

#define BT_HCI_CMD_LE_ENHANCED_RECEIVER_TEST			0x2033
typedef struct __packed {
	uint8_t rx_channel;
	uint8_t phy;
	uint8_t modulation_index;
} bt_hci_cmd_le_enhanced_receiver_test;

#define BT_HCI_CMD_LE_ENHANCED_TRANSMITTER_TEST			0x2034
typedef struct __packed {
	uint8_t tx_channel;
	uint8_t data_len;
	uint8_t payload;
	uint8_t phy;
} bt_hci_cmd_le_enhanced_transmitter_test;

#define BT_HCI_CMD_LE_SET_ADV_SET_RAND_ADDR			0x2035
typedef struct __packed {
	uint8_t  handle;
	uint8_t  bdaddr[6];
} bt_hci_cmd_le_set_adv_set_rand_addr;

#define BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS			0x2036
typedef struct __packed {
	uint8_t  handle;
	uint16_t evt_properties;
	uint8_t  min_interval[3];
	uint8_t  max_interval[3];
	uint8_t  channel_map;
	uint8_t  own_addr_type;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint8_t  filter_policy;
	uint8_t  tx_power;
	uint8_t  primary_phy;
	uint8_t  secondary_max_skip;
	uint8_t  secondary_phy;
	uint8_t  sid;
	uint8_t  notif_enable;
} bt_hci_cmd_le_set_ext_adv_params;
typedef struct __packed {
	uint8_t  status;
	uint8_t  tx_power;
} bt_hci_rsp_le_set_ext_adv_params;

#define BT_HCI_CMD_LE_SET_EXT_ADV_DATA			0x2037
typedef struct __packed {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  fragment_preference;
	uint8_t  data_len;
	uint8_t  data[0];
} bt_hci_cmd_le_set_ext_adv_data;

#define BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA			0x2038
typedef struct __packed {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  fragment_preference;
	uint8_t  data_len;
	uint8_t  data[0];
} bt_hci_cmd_le_set_ext_scan_rsp_data;

#define BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE			0x2039
typedef struct __packed {
	uint8_t  enable;
	uint8_t  num_of_sets;
} bt_hci_cmd_le_set_ext_adv_enable;
typedef struct __packed {
	uint8_t  handle;
	uint16_t duration;
	uint8_t  max_events;
} bt_hci_cmd_ext_adv_set;

#define BT_HCI_CMD_LE_READ_MAX_ADV_DATA_LEN			0x203a
typedef struct __packed {
	uint8_t  status;
	uint16_t max_len;
} bt_hci_rsp_le_read_max_adv_data_len;

#define BT_HCI_CMD_LE_READ_NUM_SUPPORTED_ADV_SETS	0x203b
typedef struct __packed {
	uint8_t  status;
	uint8_t  num_of_sets;
} bt_hci_rsp_le_read_num_supported_adv_sets;

#define BT_HCI_CMD_LE_REMOVE_ADV_SET				0x203c
typedef struct __packed {
	uint8_t  handle;
} bt_hci_cmd_le_remove_adv_set;

#define BT_HCI_CMD_LE_CLEAR_ADV_SETS				0x203d

#define BT_HCI_CMD_LE_SET_PA_PARAMS					0x203e
typedef struct __packed {
	uint8_t  handle;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t properties;
} bt_hci_cmd_le_set_pa_params;

#define BT_HCI_CMD_LE_SET_PA_DATA					0x203f
typedef struct __packed {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  data_len;
	uint8_t  data[0];
} bt_hci_cmd_le_set_pa_data;

#define BT_HCI_CMD_LE_SET_PA_ENABLE					0x2040
typedef struct __packed {
	uint8_t  enable;
	uint8_t  handle;
} bt_hci_cmd_le_set_pa_enable;

#define BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS			0x2041
typedef struct __packed {
	uint8_t  own_addr_type;
	uint8_t  filter_policy;
	uint8_t  num_phys;
	uint8_t  data[0];
} bt_hci_cmd_le_set_ext_scan_params;
typedef struct __packed {
	uint8_t  type;
	uint16_t interval;
	uint16_t window;
} bt_hci_le_scan_phy;

#define BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE			0x2042
typedef struct __packed {
	uint8_t  enable;
	uint8_t  filter_dup;
	uint16_t duration;
	uint16_t period;
} bt_hci_cmd_le_set_ext_scan_enable;

#define BT_HCI_CMD_LE_EXT_CREATE_CONN				0x2043
typedef struct __packed {
	uint8_t  filter_policy;
	uint8_t  own_addr_type;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint8_t  phys;
	uint8_t  data[0];
} bt_hci_cmd_le_ext_create_conn;
typedef struct __packed {
	uint16_t scan_interval;
	uint16_t scan_window;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t supv_timeout;
	uint16_t min_length;
	uint16_t max_length;
} bt_hci_le_ext_create_conn;

#define BT_HCI_CMD_LE_PA_CREATE_SYNC				0x2044
typedef struct __packed {
	uint8_t  options;
	uint8_t  sid;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint16_t skip;
	uint16_t sync_timeout;
	uint8_t  sync_cte_type;
} bt_hci_cmd_le_pa_create_sync;

#define BT_HCI_CMD_LE_PA_CREATE_SYNC_CANCEL			0x2045

#define BT_HCI_CMD_LE_PA_TERM_SYNC					0x2046
typedef struct __packed {
	uint16_t sync_handle;
} bt_hci_cmd_le_pa_term_sync;

#define BT_HCI_CMD_LE_ADD_DEV_PA_LIST				0x2047
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  sid;
} bt_hci_cmd_le_add_dev_pa_list;

#define BT_HCI_CMD_LE_REMOVE_DEV_PA_LIST			0x2048
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  sid;
} bt_hci_cmd_le_remove_dev_pa_list;

#define BT_HCI_CMD_LE_CLEAR_PA_LIST					0x2049

#define BT_HCI_CMD_LE_READ_PA_LIST_SIZE				0x204a
typedef struct __packed {
	uint8_t  status;
	uint8_t  list_size;
} bt_hci_rsp_le_read_dev_pa_list_size;

#define BT_HCI_CMD_LE_READ_TX_POWER					0x204b
typedef struct __packed {
	uint8_t  status;
	int8_t  min_tx_power;
	int8_t  max_tx_power;
} bt_hci_rsp_le_read_tx_power;

#define BT_HCI_CMD_LE_READ_RF_PATH_COMPENSATION		0x204c
typedef struct __packed {
	uint8_t  status;
	uint16_t rf_tx_path_comp;
	uint16_t rf_rx_path_comp;
} bt_hci_rsp_le_read_rf_path_comp;

#define BT_HCI_CMD_LE_WRITE_RF_PATH_COMPENSATION	0x204d
typedef struct __packed {
	uint16_t rf_tx_path_comp;
	uint16_t rf_rx_path_comp;
} bt_hci_cmd_le_write_rf_path_comp;

#define BT_HCI_CMD_LE_SET_PRIV_MODE					0x204e
typedef struct __packed {
	uint8_t  peer_id_addr_type;
	uint8_t  peer_id_addr[6];
	uint8_t  priv_mode;
} bt_hci_cmd_le_set_priv_mode;

#define BT_HCI_CMD_LE_RECEIVER_TEST_V3				0x204f
typedef struct __packed {
	uint8_t  rx_chan;
	uint8_t  phy;
	uint8_t  mod_index;
	uint8_t  cte_len;
	uint8_t  cte_type;
	uint8_t  duration;
	uint8_t  num_antenna_id;
	uint8_t  antenna_ids[0];
} bt_hci_cmd_le_receiver_test_v3;

#define BT_HCI_CMD_LE_TX_TEST_V3					0x2050
typedef struct __packed {
	uint8_t  chan;
	uint8_t  data_len;
	uint8_t  payload;
	uint8_t  phy;
	uint8_t  cte_len;
	uint8_t  cte_type;
	uint8_t  duration;
	uint8_t  num_antenna_id;
	uint8_t  antenna_ids[0];
} bt_hci_cmd_le_tx_test_v3;

#define BT_HCI_CMD_SET_PA_REC_ENABLE		0x2059
typedef struct __packed {
	uint16_t sync_handle;
	uint8_t  enable;
} bt_hci_cmd_set_pa_rec_enable;

#define BT_HCI_CMD_PERIODIC_SYNC_TRANS		0x205a
typedef struct __packed {
	uint16_t handle;
	uint16_t service_data;
	uint16_t sync_handle;
} bt_hci_cmd_periodic_sync_trans;

#define BT_HCI_CMD_PA_SET_INFO_TRANS		0x205b
typedef struct __packed {
	uint16_t handle;
	uint16_t service_data;
	uint8_t adv_handle;
} bt_hci_cmd_pa_set_info_trans;

#define BT_HCI_CMD_PA_SYNC_TRANS_PARAMS		0x205c
typedef struct __packed {
	uint16_t  handle;
	uint8_t   mode;
	uint16_t  skip;
	uint16_t  sync_timeout;
	uint8_t   cte_type;
} bt_hci_cmd_pa_sync_trans_params;

#define BT_HCI_CMD_DEFAULT_PA_SYNC_TRANS_PARAMS	0x205d
typedef struct __packed {
	uint8_t  mode;
	uint16_t skip;
	uint16_t sync_timeout;
	uint8_t  cte_type;
} bt_hci_cmd_default_pa_sync_trans_params;

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE_V2	0x2060
#define BT_HCI_BIT_LE_READ_BUFFER_SIZE_V2	BT_HCI_CMD_BIT(41, 5)
typedef struct __packed {
	uint8_t  status;
	uint16_t acl_mtu;
	uint8_t  acl_max_pkt;
	uint16_t iso_mtu;
	uint8_t  iso_max_pkt;
} bt_hci_rsp_le_read_buffer_size_v2;

#define BT_HCI_CMD_LE_READ_ISO_TX_SYNC		0x2061
#define BT_HCI_BIT_LE_READ_ISO_TX_SYNC		BT_HCI_CMD_BIT(41, 6)
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_read_iso_tx_sync;

typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t seq;
	uint32_t timestamp;
	uint8_t  offset[3];
} bt_hci_rsp_le_read_iso_tx_sync;

#define BT_HCI_CMD_LE_SET_CIG_PARAMS		0x2062
#define BT_HCI_BIT_LE_SET_CIG_PARAMS		BT_HCI_CMD_BIT(41, 7)
typedef struct __packed {
	uint8_t  cis_id;
	uint16_t c_sdu;
	uint16_t p_sdu;
	uint8_t  c_phy;
	uint8_t  p_phy;
	uint8_t  c_rtn;
	uint8_t  p_rtn;
} bt_hci_cis_params;

typedef struct __packed {
	uint8_t  cig_id;
	uint8_t  c_interval[3];
	uint8_t  p_interval[3];
	uint8_t  sca;
	uint8_t  packing;
	uint8_t  framing;
	uint16_t c_latency;
	uint16_t p_latency;
	uint8_t  num_cis;
	bt_hci_cis_params cis[0];
} bt_hci_cmd_le_set_cig_params;

typedef struct __packed {
	uint8_t  status;
	uint8_t  cig_id;
	uint8_t  num_handles;
	uint16_t handle[0];
} bt_hci_rsp_le_set_cig_params;

#define BT_HCI_CMD_LE_SET_CIG_PARAMS_TEST	0x2063
#define BT_HCI_BIT_LE_SET_CIG_PARAMS_TEST	BT_HCI_CMD_BIT(42, 0)
typedef struct __packed {
	uint8_t  cis_id;
	uint8_t  nse;
	uint16_t c_sdu;
	uint16_t p_sdu;
	uint16_t c_pdu;
	uint16_t p_pdu;
	uint8_t  c_phy;
	uint8_t  p_phy;
	uint8_t  c_bn;
	uint8_t  p_bn;
} bt_hci_cis_params_test;

typedef struct __packed {
	uint8_t  cig_id;
	uint8_t  c_interval[3];
	uint8_t  p_interval[3];
	uint8_t  c_ft;
	uint8_t  p_ft;
	uint16_t iso_interval;
	uint8_t  sca;
	uint8_t  packing;
	uint8_t  framing;
	uint8_t  num_cis;
	bt_hci_cis_params_test cis[0];
} bt_hci_cmd_le_set_cig_params_test;

#define BT_HCI_CMD_LE_CREATE_CIS		0x2064
#define BT_HCI_BIT_LE_CREATE_CIS		BT_HCI_CMD_BIT(42, 1)
typedef struct __packed {
	uint16_t  cis_handle;
	uint16_t  acl_handle;
} bt_hci_cis;

typedef struct __packed {
	uint8_t  num_cis;
	bt_hci_cis cis[0];
} bt_hci_cmd_le_create_cis;

#define BT_HCI_CMD_LE_REMOVE_CIG		0x2065
#define BT_HCI_BIT_LE_REMOVE_CIG		BT_HCI_CMD_BIT(42, 2)
typedef struct __packed {
	uint8_t  cig_id;
} bt_hci_cmd_le_remove_cig;

typedef struct __packed {
	uint8_t  status;
	uint8_t  cig_id;
} bt_hci_rsp_le_remove_cig;

#define BT_HCI_CMD_LE_ACCEPT_CIS		0x2066
#define BT_HCI_BIT_LE_ACCEPT_CIS		BT_HCI_CMD_BIT(42, 3)
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_accept_cis;

#define BT_HCI_CMD_LE_REJECT_CIS		0x2067
#define BT_HCI_BIT_LE_REJECT_CIS		BT_HCI_CMD_BIT(42, 4)
typedef struct __packed {
	uint16_t handle;
	uint8_t  reason;
} bt_hci_cmd_le_reject_cis;

#define BT_HCI_CMD_LE_CREATE_BIG		0x2068
#define BT_HCI_BIT_LE_CREATE_BIG		BT_HCI_CMD_BIT(42, 5)
typedef struct __packed {
	uint8_t  sdu_interval[3];
	uint16_t sdu;
	uint16_t latency;
	uint8_t  rtn;
	uint8_t  phy;
	uint8_t  packing;
	uint8_t  framing;
	uint8_t  encryption;
	uint8_t  bcode[16];
} bt_hci_bis;

typedef struct __packed {
	uint8_t  handle;
	uint8_t  adv_handle;
	uint8_t  num_bis;
	bt_hci_bis bis;
} bt_hci_cmd_le_create_big;

#define BT_HCI_CMD_LE_CREATE_BIG_TEST		0x2069
#define BT_HCI_BIT_LE_CREATE_BIG_TEST		BT_HCI_CMD_BIT(42, 6)
typedef struct __packed {
	uint8_t  sdu_interval[3];
	uint16_t iso_interval;
	uint8_t  nse;
	uint16_t sdu;
	uint16_t  pdu;
	uint8_t  phy;
	uint8_t  packing;
	uint8_t  framing;
	uint8_t  bn;
	uint8_t  irc;
	uint8_t  pto;
	uint8_t  encryption;
	uint8_t  bcode[16];
} bt_hci_bis_test;

typedef struct __packed {
	uint8_t  big_handle;
	uint8_t  adv_handle;
	uint8_t  num_bis;
	bt_hci_bis_test bis[0];
} bt_hci_cmd_le_create_big_test;

#define BT_HCI_CMD_LE_TERM_BIG			0x206a
#define BT_HCI_BIT_LE_TERM_BIG			BT_HCI_CMD_BIT(42, 7)
typedef struct __packed {
	uint8_t  handle;
	uint8_t  reason;
} bt_hci_cmd_le_term_big;

#define BT_HCI_CMD_LE_BIG_CREATE_SYNC		0x206b
#define BT_HCI_BIT_LE_BIG_CREATE_SYNC		BT_HCI_CMD_BIT(43, 0)
typedef struct __packed {
	uint8_t  index;
} bt_hci_bis_sync;

typedef struct __packed {
	uint8_t  handle;
	uint16_t sync_handle;
	uint8_t  encryption;
	uint8_t  bcode[16];
	uint8_t  mse;
	uint16_t timeout;
	uint8_t  num_bis;
	bt_hci_bis_sync bis[0];
} bt_hci_cmd_le_big_create_sync;

#define BT_HCI_CMD_LE_BIG_TERM_SYNC		0x206c
#define BT_HCI_BIT_LE_BIG_TERM_SYNC		BT_HCI_CMD_BIT(43, 1)
typedef struct __packed {
	uint8_t  handle;
} bt_hci_cmd_le_big_term_sync;

typedef struct __packed {
	uint8_t  status;
	uint8_t  handle;
} bt_hci_rsp_le_big_term_sync;

#define BT_HCI_CMD_LE_REQ_PEER_SCA		0x206d
#define BT_HCI_BIT_LE_REQ_PEER_SCA		BT_HCI_CMD_BIT(43, 2)
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_req_peer_sca;

#define BT_HCI_CMD_LE_SETUP_ISO_PATH		0x206e
#define BT_HCI_BIT_LE_SETUP_ISO_PATH		BT_HCI_CMD_BIT(43, 3)
typedef struct __packed {
	uint16_t handle;
	uint8_t  direction;
	uint8_t  path;
	uint8_t  codec;
	uint16_t codec_cid;
	uint16_t codec_vid;
	uint8_t  delay[3];
	uint8_t  codec_cfg_len;
	uint8_t  codec_cfg[0];
} bt_hci_cmd_le_setup_iso_path;

typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_setup_iso_path;

#define BT_HCI_CMD_LE_REMOVE_ISO_PATH		0x206f
#define BT_HCI_BIT_LE_REMOVE_ISO_PATH		BT_HCI_CMD_BIT(43, 4)
typedef struct __packed {
	uint16_t handle;
	uint8_t  direction;
} bt_hci_cmd_le_remove_iso_path;

typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_rsp_le_remove_iso_path;

#define BT_HCI_CMD_LE_ISO_TX_TEST		0x2070
#define BT_HCI_BIT_LE_ISO_TX_TEST		BT_HCI_CMD_BIT(43, 5)

#define BT_HCI_CMD_LE_ISO_RX_TEST		0x2071
#define BT_HCI_BIT_LE_ISO_RX_TEST		BT_HCI_CMD_BIT(43, 6)

#define BT_HCI_CMD_LE_ISO_READ_TEST_COUNTER	0x2072
#define BT_HCI_BIT_LE_ISO_READ_TEST_COUNTER	BT_HCI_CMD_BIT(43, 7)

#define BT_HCI_CMD_LE_ISO_TEST_END		0x2073
#define BT_HCI_BIT_LE_ISO_TEST_END		BT_HCI_CMD_BIT(44, 0)

#define BT_HCI_CMD_LE_SET_HOST_FEATURE		0x2074
#define BT_HCI_BIT_LE_SET_HOST_FEATURE		BT_HCI_CMD_BIT(44, 1)
typedef struct __packed {
	uint8_t  bit_number;
	uint8_t  bit_value;
} bt_hci_cmd_le_set_host_feature;

#define BT_HCI_CMD_LE_READ_ISO_LINK_QUALITY	0x2075
#define BT_HCI_BIT_LE_READ_ISO_LINK_QUALITY	BT_HCI_CMD_BIT(45, 1)
typedef struct __packed {
	uint16_t handle;
} bt_hci_cmd_le_read_iso_link_quality;

typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint32_t tx_unacked_packets;
	uint32_t tx_flushed_packets;
	uint32_t tx_last_subevent_packets;
	uint32_t retransmitted_packets;
	uint32_t crc_error_packets;
	uint32_t rx_unreceived_packets;
	uint32_t duplicated_packets;
} bt_hci_rsp_le_read_iso_link_quality;

/* HCI Events Start */
#define BT_HCI_EVT_INQUIRY_COMPLETE		0x01
typedef struct __packed {
	uint8_t  status;
} bt_hci_evt_inquiry_complete;

#define BT_HCI_EVT_INQUIRY_RESULT		0x02
typedef struct __packed {
	uint8_t  num_resp;
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  pscan_mode;
	uint8_t  dev_class[3];
	uint16_t clock_offset;
} bt_hci_evt_inquiry_result;

#define BT_HCI_EVT_CONN_COMPLETE		0x03
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  bdaddr[6];
	uint8_t  link_type;
	uint8_t  encr_mode;
} bt_hci_evt_conn_complete;

#define BT_HCI_EVT_CONN_REQUEST			0x04
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  dev_class[3];
	uint8_t  link_type;
} bt_hci_evt_conn_request;

#define BT_HCI_EVT_DISCONNECT_COMPLETE		0x05
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  reason;
} bt_hci_evt_disconnect_complete;

#define BT_HCI_EVT_AUTH_COMPLETE		0x06
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_evt_auth_complete;

#define BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE	0x07
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint8_t  name[248];
} bt_hci_evt_remote_name_request_complete;

#define BT_HCI_EVT_ENCRYPT_CHANGE		0x08
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  encr_mode;
} bt_hci_evt_encrypt_change;

#define BT_HCI_EVT_CHANGE_CONN_LINK_KEY_COMPLETE 0x09
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_evt_change_conn_link_key_complete;

#define BT_HCI_EVT_LINK_KEY_TYPE_CHANGED	0x0a
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  key_flag;
} bt_hci_evt_link_key_type_changed;

#define BT_HCI_EVT_REMOTE_FEATURES_COMPLETE	0x0b
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  features[8];
} bt_hci_evt_remote_features_complete;

#define BT_HCI_EVT_REMOTE_VERSION_COMPLETE	0x0c
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  lmp_ver;
	uint16_t manufacturer;
	uint16_t lmp_subver;
} bt_hci_evt_remote_version_complete;

#define BT_HCI_EVT_QOS_SETUP_COMPLETE		0x0d
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  flags;
	uint8_t  service_type;
	uint32_t token_rate;
	uint32_t peak_bandwidth;
	uint32_t latency;
	uint32_t delay_variation;
} bt_hci_evt_qos_setup_complete;

#define BT_HCI_EVT_CMD_COMPLETE			0x0e
typedef struct __packed {
	uint8_t  ncmd;
	uint16_t opcode;
	uint8_t	 params[];
} bt_hci_evt_cmd_complete;

#define BT_HCI_EVT_CMD_STATUS			0x0f
typedef struct __packed {
	uint8_t  status;
	uint8_t  ncmd;
	uint16_t opcode;
} bt_hci_evt_cmd_status;

#define BT_HCI_EVT_HARDWARE_ERROR		0x10
typedef struct __packed {
	uint8_t  code;
} bt_hci_evt_hardware_error;

#define BT_HCI_EVT_FLUSH_OCCURRED		0x11
typedef struct __packed {
	uint16_t handle;
} bt_hci_evt_flush_occurred;

#define BT_HCI_EVT_ROLE_CHANGE			0x12
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint8_t  role;
} bt_hci_evt_role_change;

#define BT_HCI_EVT_NUM_COMPLETED_PACKETS	0x13
typedef struct __packed {
	uint8_t  num_handles;
	uint16_t handle;
	uint16_t count;
} bt_hci_evt_num_completed_packets;

#define BT_HCI_EVT_MODE_CHANGE			0x14
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  mode;
	uint16_t interval;
} bt_hci_evt_mode_change;

#define BT_HCI_EVT_RETURN_LINK_KEYS		0x15
typedef struct __packed {
	uint8_t  num_keys;
	uint8_t  keys[0];
} bt_hci_evt_return_link_keys;

#define BT_HCI_EVT_PIN_CODE_REQUEST		0x16
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_evt_pin_code_request;

#define BT_HCI_EVT_LINK_KEY_REQUEST		0x17
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_evt_link_key_request;

#define BT_HCI_EVT_LINK_KEY_NOTIFY			0x18
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  link_key[16];
	uint8_t  key_type;
} bt_hci_evt_link_key_notify;

#define BT_HCI_EVT_LOOPBACK_COMMAND			0x19

#define BT_HCI_EVT_DATA_BUFFER_OVERFLOW		0x1a
typedef struct __packed {
	uint8_t  link_type;
} bt_hci_evt_data_buffer_overflow;

#define BT_HCI_EVT_MAX_SLOTS_CHANGE			0x1b
typedef struct __packed {
	uint16_t handle;
	uint8_t  max_slots;
} bt_hci_evt_max_slots_change;

#define BT_HCI_EVT_CLOCK_OFFSET_COMPLETE	0x1c
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t clock_offset;
} bt_hci_evt_clock_offset_complete;

#define BT_HCI_EVT_CONN_PKT_TYPE_CHANGED	0x1d
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t pkt_type;
} bt_hci_evt_conn_pkt_type_changed;

#define BT_HCI_EVT_QOS_VIOLATION			0x1e
typedef struct __packed {
	uint16_t handle;
} bt_hci_evt_qos_violation;

#define BT_HCI_EVT_PSCAN_MODE_CHANGE		0x1f
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  pscan_mode;
} bt_hci_evt_pscan_mode_change;

#define BT_HCI_EVT_PSCAN_REP_MODE_CHANGE	0x20
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
} bt_hci_evt_pscan_rep_mode_change;

#define BT_HCI_EVT_FLOW_SPEC_COMPLETE		0x21
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  flags;
	uint8_t  direction;
	uint8_t  service_type;
	uint32_t token_rate;
	uint32_t token_bucket_size;
	uint32_t peak_bandwidth;
	uint32_t access_latency;
} bt_hci_evt_flow_spec_complete;

#define BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI	0x22
typedef struct __packed {
	uint8_t  num_resp;
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  dev_class[3];
	uint16_t clock_offset;
	int8_t   rssi;
} bt_hci_evt_inquiry_result_with_rssi;

#define BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE	0x23
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  page;
	uint8_t  max_page;
	uint8_t  features[8];
} bt_hci_evt_remote_ext_features_complete;

#define BT_HCI_EVT_SYNC_CONN_COMPLETE		0x2c
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  bdaddr[6];
	uint8_t  link_type;
	uint8_t  tx_interval;
	uint8_t  retrans_window;
	uint16_t rx_pkt_len;
	uint16_t tx_pkt_len;
	uint8_t  air_mode;
} bt_hci_evt_sync_conn_complete;

#define BT_HCI_EVT_SYNC_CONN_CHANGED		0x2d
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  tx_interval;
	uint8_t  retrans_window;
	uint16_t rx_pkt_len;
	uint16_t tx_pkt_len;
} bt_hci_evt_sync_conn_changed;

#define BT_HCI_EVT_SNIFF_SUBRATING			0x2e
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t max_tx_latency;
	uint16_t max_rx_latency;
	uint16_t min_remote_timeout;
	uint16_t min_local_timeout;
} bt_hci_evt_sniff_subrating;

#define BT_HCI_EVT_EXT_INQUIRY_RESULT		0x2f
typedef struct __packed {
	uint8_t  num_resp;
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  dev_class[3];
	uint16_t clock_offset;
	int8_t   rssi;
	uint8_t  data[240];
} bt_hci_evt_ext_inquiry_result;

#define BT_HCI_EVT_ENCRYPT_KEY_REFRESH_COMPLETE	0x30
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_evt_encrypt_key_refresh_complete;

#define BT_HCI_EVT_IO_CAPABILITY_REQUEST	0x31
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_evt_io_capability_request;

#define BT_HCI_EVT_IO_CAPABILITY_RESPONSE	0x32
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  capability;
	uint8_t  oob_data;
	uint8_t  authentication;
} bt_hci_evt_io_capability_response;

#define BT_HCI_EVT_USER_CONFIRM_REQUEST		0x33
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint32_t passkey;
} bt_hci_evt_user_confirm_request;

#define BT_HCI_EVT_USER_PASSKEY_REQUEST		0x34
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_evt_user_passkey_request;

#define BT_HCI_EVT_REMOTE_OOB_DATA_REQUEST	0x35
typedef struct __packed {
	uint8_t  bdaddr[6];
} bt_hci_evt_remote_oob_data_request;

#define BT_HCI_EVT_SIMPLE_PAIRING_COMPLETE	0x36
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_evt_simple_pairing_complete;

#define BT_HCI_EVT_LINK_SUPV_TIMEOUT_CHANGED	0x38
typedef struct __packed {
	uint16_t handle;
	uint16_t timeout;
} bt_hci_evt_link_supv_timeout_changed;

#define BT_HCI_EVT_ENHANCED_FLUSH_COMPLETE		0x39
typedef struct __packed {
	uint16_t handle;
} bt_hci_evt_enhanced_flush_complete;

#define BT_HCI_EVT_USER_PASSKEY_NOTIFY			0x3b
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint32_t passkey;
} bt_hci_evt_user_passkey_notify;

#define BT_HCI_EVT_KEYPRESS_NOTIFY				0x3c
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  type;
} bt_hci_evt_keypress_notify;

#define BT_HCI_EVT_REMOTE_HOST_FEATURES_NOTIFY	0x3d
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  features[8];
} bt_hci_evt_remote_host_features_notify;

#define BT_HCI_EVT_LE_META_EVENT				0x3e

#define BT_HCI_EVT_PHY_LINK_COMPLETE			0x40
typedef struct __packed {
	uint8_t  status;
	uint8_t  phy_handle;
} bt_hci_evt_phy_link_complete;

#define BT_HCI_EVT_CHANNEL_SELECTED				0x41
typedef struct __packed {
	uint8_t  phy_handle;
} bt_hci_evt_channel_selected;

#define BT_HCI_EVT_DISCONN_PHY_LINK_COMPLETE	0x42
typedef struct __packed {
	uint8_t  status;
	uint8_t  phy_handle;
	uint8_t  reason;
} bt_hci_evt_disconn_phy_link_complete;

#define BT_HCI_EVT_PHY_LINK_LOSS_EARLY_WARNING	0x43
typedef struct __packed {
	uint8_t  phy_handle;
	uint8_t  reason;
} bt_hci_evt_phy_link_loss_early_warning;

#define BT_HCI_EVT_PHY_LINK_RECOVERY			0x44
typedef struct __packed {
	uint8_t  phy_handle;
} bt_hci_evt_phy_link_recovery;

#define BT_HCI_EVT_LOGIC_LINK_COMPLETE			0x45
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  phy_handle;
	uint8_t  flow_spec;
} bt_hci_evt_logic_link_complete;

#define BT_HCI_EVT_DISCONN_LOGIC_LINK_COMPLETE	0x46
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  reason;
} bt_hci_evt_disconn_logic_link_complete;

#define BT_HCI_EVT_FLOW_SPEC_MODIFY_COMPLETE	0x47
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_evt_flow_spec_modify_complete;

#define BT_HCI_EVT_NUM_COMPLETED_DATA_BLOCKS	0x48
typedef struct __packed {
	uint16_t total_num_blocks;
	uint8_t  num_handles;
	uint16_t handle;
	uint16_t num_packets;
	uint16_t num_blocks;
} bt_hci_evt_num_completed_data_blocks;

#define BT_HCI_EVT_AMP_START_TEST				0x49

#define BT_HCI_EVT_AMP_TEST_END					0x4a

#define BT_HCI_EVT_AMP_REC_REPORT				0x4b

#define BT_HCI_EVT_SHORT_RANGE_MODE_CHANGE		0x4c
typedef struct __packed {
	uint8_t  status;
	uint8_t  phy_handle;
	uint8_t  mode;
} bt_hci_evt_short_range_mode_change;

#define BT_HCI_EVT_AMP_STATUS_CHANGE			0x4d
typedef struct __packed {
	uint8_t  status;
	uint8_t  amp_status;
} bt_hci_evt_amp_status_change;

#define BT_HCI_EVT_TRIGGERED_CLOCK_CAPTURE		0x4e
typedef struct __packed {
	uint16_t handle;
	uint8_t  type;
	uint32_t clock;
	uint16_t clock_offset;
} bt_hci_evt_triggered_clock_capture;

#define BT_HCI_EVT_SYNC_TRAIN_COMPLETE			0x4f
typedef struct __packed {
	uint8_t  status;
} bt_hci_evt_sync_train_complete;

#define BT_HCI_EVT_SYNC_TRAIN_RECEIVED			0x50
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint32_t offset;
	uint8_t  map[10];
	uint8_t  lt_addr;
	uint32_t instant;
	uint16_t interval;
	uint8_t  service_data;
} bt_hci_evt_sync_train_received;

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_RECEIVE	0x51
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  lt_addr;
	uint32_t clock;
	uint32_t offset;
	uint8_t  status;
	uint8_t  fragment;
	uint8_t  length;
} bt_hci_evt_peripheral_broadcast_receive;

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_TIMEOUT	0x52
typedef struct __packed {
	uint8_t  bdaddr[6];
	uint8_t  lt_addr;
} bt_hci_evt_peripheral_broadcast_timeout;

#define BT_HCI_EVT_TRUNCATED_PAGE_COMPLETE		0x53
typedef struct __packed {
	uint8_t  status;
	uint8_t  bdaddr[6];
} bt_hci_evt_truncated_page_complete;

#define BT_HCI_EVT_PERIPHERAL_PAGE_RESPONSE_TIMEOUT	0x54

#define BT_HCI_EVT_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE	0x55
typedef struct __packed {
	uint8_t  map[10];
} bt_hci_evt_channel_map_change;

#define BT_HCI_EVT_INQUIRY_RESPONSE_NOTIFY	0x56
typedef struct __packed {
	uint8_t  lap[3];
	int8_t   rssi;
} bt_hci_evt_inquiry_response_notify;

#define BT_HCI_EVT_AUTH_PAYLOAD_TIMEOUT_EXPIRED	0x57
typedef struct __packed {
	uint16_t handle;
} bt_hci_evt_auth_payload_timeout_expired;

#define BT_HCI_EVT_SAM_STATUS_CHANGE			0x58

#define BT_HCI_EVT_ENCRYPT_CHANGE_V2			0x59

#define BT_HCI_EVT_LE_CONN_COMPLETE				0x01
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  role;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint16_t interval;
	uint16_t latency;
	uint16_t supv_timeout;
	uint8_t  clock_accuracy;
} bt_hci_evt_le_conn_complete;

#define BT_HCI_EVT_LE_ADV_REPORT				0x02
typedef struct __packed {
	uint8_t  num_reports;
	uint8_t  event_type;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  data_len;
	uint8_t  data[0];
} bt_hci_evt_le_adv_report;

#define BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE		0x03
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t interval;
	uint16_t latency;
	uint16_t supv_timeout;
} bt_hci_evt_le_conn_update_complete;

#define BT_HCI_EVT_LE_REMOTE_FEATURES_COMPLETE	0x04
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  features[8];
} bt_hci_evt_le_remote_features_complete;

#define BT_HCI_EVT_LE_LONG_TERM_KEY_REQUEST		0x05
typedef struct __packed {
	uint16_t handle;
	uint64_t rand;
	uint16_t ediv;
} bt_hci_evt_le_long_term_key_request;

#define BT_HCI_EVT_LE_CONN_PARAM_REQUEST		0x06
typedef struct __packed {
	uint16_t handle;
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t supv_timeout;
} bt_hci_evt_le_conn_param_request;

#define BT_HCI_EVT_LE_DATA_LENGTH_CHANGE		0x07
typedef struct __packed {
	uint16_t handle;
	uint16_t max_tx_len;
	uint16_t max_tx_time;
	uint16_t max_rx_len;
	uint16_t max_rx_time;
} bt_hci_evt_le_data_length_change;

#define BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE	0x08
typedef struct __packed {
	uint8_t  status;
	uint8_t  local_pk256[64];
} bt_hci_evt_le_read_local_pk256_complete;

#define BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE	0x09
typedef struct __packed {
	uint8_t  status;
	uint8_t  dhkey[32];
} bt_hci_evt_le_generate_dhkey_complete;

#define BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE	0x0a
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  role;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint8_t  local_rpa[6];
	uint8_t  peer_rpa[6];
	uint16_t interval;
	uint16_t latency;
	uint16_t supv_timeout;
	uint8_t  clock_accuracy;
} bt_hci_evt_le_enhanced_conn_complete;

#define BT_HCI_EVT_LE_DIRECT_ADV_REPORT		0x0b
typedef struct __packed {
	uint8_t  num_reports;
	uint8_t  event_type;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  direct_addr_type;
	uint8_t  direct_addr[6];
	int8_t   rssi;
} bt_hci_evt_le_direct_adv_report;

#define BT_HCI_EVT_LE_PHY_UPDATE_COMPLETE	0x0c
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  tx_phy;
	uint8_t  rx_phy;
} bt_hci_evt_le_phy_update_complete;

#define BT_HCI_EVT_LE_EXT_ADV_REPORT		0x0d
typedef struct __packed {
	uint8_t  num_reports;
} bt_hci_evt_le_ext_adv_report;
typedef struct __packed {
	uint16_t event_type;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  primary_phy;
	uint8_t  secondary_phy;
	uint8_t  sid;
	uint8_t  tx_power;
	int8_t   rssi;
	uint16_t interval;
	uint8_t  direct_addr_type;
	uint8_t  direct_addr[6];
	uint8_t  data_len;
	uint8_t  data[0];
} bt_hci_le_ext_adv_report;

#define BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED	0x0e
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  sid;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  phy;
	uint16_t interval;
	uint8_t  clock_accuracy;
} bt_hci_evt_le_per_sync_established;

typedef struct __packed {
	uint8_t  id;
	uint16_t cid;
	uint16_t vid;
} bt_hci_le_pa_base_codec;

typedef struct __packed {
	uint8_t  len;
	uint8_t  data[];
} bt_hci_lv_data;

// typedef struct __packed {
// 	uint8_t  index;
// 	bt_hci_lv_data codec_cfg[];
// } bt_hci_lv_data;

typedef struct __packed {
	uint8_t  num_bis;
	bt_hci_le_pa_base_codec codec;
	uint8_t  data[];
} bt_hci_le_pa_base_subgroup;

typedef struct __packed {
	uint8_t  pd[3];
	uint8_t  num_subgroups;
	bt_hci_le_pa_base_subgroup subgroups[];
} bt_hci_le_pa_base_data;

#define BT_HCI_EVT_LE_PA_REPORT			0x0f
typedef struct __packed {
	uint16_t handle;
	uint8_t  tx_power;
	int8_t   rssi;
	uint8_t  cte_type;
	uint8_t  data_status;
	uint8_t  data_len;
	uint8_t  data[0];
} bt_hci_le_pa_report;

#define BT_HCI_EVT_LE_PA_SYNC_LOST		0x10
typedef struct __packed {
	uint16_t handle;
} bt_hci_evt_le_per_sync_lost;

#define BT_HCI_EVT_LE_SCAN_TMOUT		0x11

#define BT_HCI_EVT_LE_ADV_SET_TERM		0x12
typedef struct __packed {
	uint8_t  status;
	uint8_t  handle;
	uint16_t conn_handle;
	uint8_t  num_evts;
} bt_hci_evt_le_adv_set_term;

#define BT_HCI_EVT_LE_SCAN_REQ_RECEIVED		0x13
typedef struct __packed {
	uint8_t  handle;
	uint8_t  scanner_addr_type;
	uint8_t  scanner_addr[6];
} bt_hci_evt_le_scan_req_received;

#define BT_HCI_EVT_LE_CHAN_SELECT_ALG		0x14
typedef struct __packed {
	uint16_t handle;
	uint8_t  algorithm;
} bt_hci_evt_le_chan_select_alg;

#define BT_HCI_EVT_LE_CONNLESS_IQ_REPORT	0x15

#define BT_HCI_EVT_LE_CONN_IQ_REPORT		0x16

#define BT_HCI_EVT_LE_CTE_REQUEST_FAILED	0x17
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
} bt_hci_evt_le_cte_request_failed;

#define BT_HCI_EVT_LE_PA_SYNC_TRANS_REC		0x18
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint16_t service_data;
	uint16_t sync_handle;
	uint8_t  sid;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  phy;
	uint16_t interval;
	uint8_t  clock_accuracy;
} bt_hci_evt_le_pa_sync_trans_rec;

#define BT_HCI_EVT_LE_CIS_ESTABLISHED		0x19
typedef struct __packed {
	uint8_t  status;
	uint16_t conn_handle;
	uint8_t  cig_sync_delay[3];
	uint8_t  cis_sync_delay[3];
	uint8_t  c_latency[3];
	uint8_t  p_latency[3];
	uint8_t  c_phy;
	uint8_t  p_phy;
	uint8_t  nse;
	uint8_t  c_bn;
	uint8_t  p_bn;
	uint8_t  c_ft;
	uint8_t  p_ft;
	uint16_t c_mtu;
	uint16_t p_mtu;
	uint16_t interval;
} bt_hci_evt_le_cis_established;

#define BT_HCI_EVT_LE_CIS_REQ				0x1a
typedef struct __packed {
	uint16_t acl_handle;
	uint16_t cis_handle;
	uint8_t  cig_id;
	uint8_t  cis_id;
} bt_hci_evt_le_cis_req;

#define BT_HCI_EVT_LE_BIG_COMPLETE			0x1b
typedef struct __packed {
	uint8_t  status;
	uint8_t  handle;
	uint8_t  sync_delay[3];
	uint8_t  latency[3];
	uint8_t  phy;
	uint8_t  nse;
	uint8_t  bn;
	uint8_t  pto;
	uint8_t  irc;
	uint16_t max_pdu;
	uint16_t interval;
	uint8_t  num_bis;
	uint16_t bis_handle[0];
} bt_hci_evt_le_big_complete;

#define BT_HCI_EVT_LE_BIG_TERMINATE			0x1c
typedef struct __packed {
	uint8_t  handle;
	uint8_t  reason;
} bt_hci_evt_le_big_terminate;

#define BT_HCI_EVT_LE_BIG_SYNC_ESTABILISHED	0x1d
typedef struct __packed {
	uint8_t  status;
	uint8_t  handle;
	uint8_t  latency[3];
	uint8_t  nse;
	uint8_t  bn;
	uint8_t  pto;
	uint8_t  irc;
	uint16_t max_pdu;
	uint16_t interval;
	uint8_t  num_bis;
	uint16_t bis[0];
} bt_hci_evt_le_big_sync_estabilished;

#define BT_HCI_EVT_LE_BIG_SYNC_LOST			0x1e
typedef struct __packed {
	uint8_t  big_handle;
	uint8_t  reason;
} bt_hci_evt_le_big_sync_lost;

#define BT_HCI_EVT_LE_REQ_PEER_SCA_COMPLETE	0x1f
typedef struct __packed {
	uint8_t  status;
	uint16_t handle;
	uint8_t  sca;
} bt_hci_evt_le_req_peer_sca_complete;

#define BT_HCI_EVT_LE_PATH_LOSS_THRESH		0x20

#define BT_HCI_EVT_LE_TRANSMIT_POWER_REPORT	0x21

#define BT_HCI_EVT_LE_BIG_INFO_ADV_REPORT	0x22
typedef struct __packed {
	uint16_t sync_handle;
	uint8_t  num_bis;
	uint8_t  nse;
	uint16_t iso_interval;
	uint8_t  bn;
	uint8_t  pto;
	uint8_t  irc;
	uint16_t max_pdu;
	uint8_t  sdu_interval[3];
	uint16_t max_sdu;
	uint8_t  phy;
	uint8_t  framing;
	uint8_t  encryption;
} bt_hci_evt_le_big_info_adv_report;

#define BT_HCI_EVT_LE_SUBRATE_CHANGE			0x23

#define BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED_V2	0x24

#define BT_HCI_EVT_LE_PA_REPORT_V2				0x25

#define BT_HCI_EVT_LE_PA_SYNC_TRANS_REC_V2		0x26

#define BT_HCI_EVT_LE_PA_SUBEVENT_REQ			0x27

#define BT_HCI_EVT_LE_PA_RESP_REPORT			0x28

#define BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE_V2	0x29


#define BT_HCI_ERR_SUCCESS					0x00
#define BT_HCI_ERR_UNKNOWN_COMMAND			0x01
#define BT_HCI_ERR_UNKNOWN_CONN_ID			0x02
#define BT_HCI_ERR_HARDWARE_FAILURE			0x03
#define BT_HCI_ERR_PAGE_TIMEOUT				0x04
#define BT_HCI_ERR_AUTH_FAILURE				0x05
#define BT_HCI_ERR_PIN_OR_KEY_MISSING		0x06
#define BT_HCI_ERR_MEM_CAPACITY_EXCEEDED	0x07
#define BT_HCI_ERR_CONN_ALREADY_EXISTS		0x0b
#define BT_HCI_ERR_COMMAND_DISALLOWED		0x0c
#define BT_HCI_ERR_UNSUPPORTED_FEATURE		0x11
#define BT_HCI_ERR_INVALID_PARAMETERS		0x12
#define BT_HCI_ERR_LOCAL_HOST_TERM			0x16
#define BT_HCI_ERR_UNSPECIFIED_ERROR		0x1f
#define BT_HCI_ERR_ADV_TIMEOUT				0x3c
#define BT_HCI_ERR_CONN_FAILED_TO_ESTABLISH	0x3e
#define BT_HCI_ERR_UNKNOWN_ADVERTISING_ID	0x42
#define BT_HCI_ERR_CANCELLED				0x44
#define BT_HCI_ERR_ENC_MODE_NOT_ACCEPTABLE	0x25

/* L2CAP Start */
#define BT_L2CAP_CID_SIG		1
#define BT_L2CAP_CID_ATT		4
#define BT_L2CAP_CID_SIG_LE		5
#define BT_L2CAP_CID_SMP		6
#define BT_L2CAP_CID_SMP_BREDR	7

typedef struct __packed {
	uint16_t len;
	uint16_t cid;
	uint8_t  data[];
} bt_l2cap_hdr;

typedef struct __packed {
	uint8_t  code;
	uint8_t  ident;
	uint16_t len;
	uint8_t data[];
} bt_l2cap_sig_hdr;

#define BT_L2CAP_PDU_CMD_REJECT		0x01
typedef struct __packed {
	uint16_t reason;
} bt_l2cap_pdu_cmd_reject;

#define BT_L2CAP_PDU_CONN_REQ		0x02
typedef struct __packed {
	uint16_t psm;
	uint16_t scid;
} bt_l2cap_pdu_conn_req;

#define BT_L2CAP_PDU_CONN_RSP		0x03
typedef struct __packed {
	uint16_t dcid;
	uint16_t scid;
	uint16_t result;
	uint16_t status;
} bt_l2cap_pdu_conn_rsp;

#define BT_L2CAP_PDU_CONFIG_REQ		0x04
typedef struct __packed {
	uint16_t dcid;
	uint16_t flags;
} bt_l2cap_pdu_config_req;

#define BT_L2CAP_PDU_CONFIG_RSP		0x05
typedef struct __packed {
	uint16_t scid;
	uint16_t flags;
	uint16_t result;
} bt_l2cap_pdu_config_rsp;

#define BT_L2CAP_PDU_DISCONN_REQ	0x06
typedef struct __packed {
	uint16_t dcid;
	uint16_t scid;
} bt_l2cap_pdu_disconn_req;

#define BT_L2CAP_PDU_DISCONN_RSP	0x07
typedef struct __packed {
	uint16_t dcid;
	uint16_t scid;
} bt_l2cap_pdu_disconn_rsp;

#define BT_L2CAP_PDU_ECHO_REQ		0x08

#define BT_L2CAP_PDU_ECHO_RSP		0x09

#define BT_L2CAP_PDU_INFO_REQ		0x0a
typedef struct __packed {
	uint16_t type;
} bt_l2cap_pdu_info_req;

#define BT_L2CAP_PDU_INFO_RSP		0x0b
typedef struct __packed {
	uint16_t type;
	uint16_t result;
	uint8_t  data[0];
} bt_l2cap_pdu_info_rsp;

#define BT_L2CAP_PDU_CREATE_CHAN_REQ	0x0c
typedef struct __packed {
	uint16_t psm;
	uint16_t scid;
	uint8_t  ctrlid;
} bt_l2cap_pdu_create_chan_req;

#define BT_L2CAP_PDU_CREATE_CHAN_RSP	0x0d
typedef struct __packed {
	uint16_t dcid;
	uint16_t scid;
	uint16_t result;
	uint16_t status;
} bt_l2cap_pdu_create_chan_rsp;

#define BT_L2CAP_PDU_MOVE_CHAN_REQ		0x0e
typedef struct __packed {
	uint16_t icid;
	uint8_t  ctrlid;
} bt_l2cap_pdu_move_chan_req;

#define BT_L2CAP_PDU_MOVE_CHAN_RSP		0x0f
typedef struct __packed {
	uint16_t icid;
	uint16_t result;
} bt_l2cap_pdu_move_chan_rsp;

#define BT_L2CAP_PDU_MOVE_CHAN_CFM		0x10
typedef struct __packed {
	uint16_t icid;
	uint16_t result;
} bt_l2cap_pdu_move_chan_cfm;

#define BT_L2CAP_PDU_MOVE_CHAN_CFM_RSP	0x11
typedef struct __packed {
	uint16_t icid;
} bt_l2cap_pdu_move_chan_cfm_rsp;

#define BT_L2CAP_PDU_CONN_PARAM_REQ		0x12
typedef struct __packed {
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t timeout;
} bt_l2cap_pdu_conn_param_req;

#define BT_L2CAP_PDU_CONN_PARAM_RSP		0x13
typedef struct __packed {
	uint16_t result;
} bt_l2cap_pdu_conn_param_rsp;

#define BT_L2CAP_PDU_LE_CONN_REQ		0x14
typedef struct __packed {
	uint16_t psm;
	uint16_t scid;
	uint16_t mtu;
	uint16_t mps;
	uint16_t credits;
} bt_l2cap_pdu_le_conn_req;

#define BT_L2CAP_PDU_LE_CONN_RSP		0x15
typedef struct __packed {
	uint16_t dcid;
	uint16_t mtu;
	uint16_t mps;
	uint16_t credits;
	uint16_t result;
} bt_l2cap_pdu_le_conn_rsp;

#define BT_L2CAP_PDU_LE_FLOWCTL_CREDS	0x16
typedef struct __packed {
	uint16_t cid;
	uint16_t credits;
} bt_l2cap_pdu_le_flowctl_creds;

#define BT_L2CAP_PDU_ECRED_CONN_REQ		0x17
typedef struct __packed {
	uint16_t psm;
	uint16_t mtu;
	uint16_t mps;
	uint16_t credits;
	uint16_t scid[0];
} bt_l2cap_pdu_ecred_conn_req;

#define BT_L2CAP_PDU_ECRED_CONN_RSP		0x18
typedef struct __packed {
	uint16_t mtu;
	uint16_t mps;
	uint16_t credits;
	uint16_t result;
	uint16_t dcid[0];
} bt_l2cap_pdu_ecred_conn_rsp;

#define BT_L2CAP_PDU_ECRED_RECONF_REQ	0x19
typedef struct __packed {
	uint16_t mtu;
	uint16_t mps;
	uint16_t scid[0];
} bt_l2cap_pdu_ecred_reconf_req;

#define BT_L2CAP_PDU_ECRED_RECONF_RSP	0x1a
typedef struct __packed {
	uint16_t result;
} bt_l2cap_pdu_ecred_reconf_rsp;

typedef struct __packed {
	uint16_t psm;
} bt_l2cap_hdr_connless;

typedef struct __packed {
	uint8_t  code;
	uint8_t  ident;
	uint16_t len;
} bt_l2cap_hdr_amp;

#define BT_L2CAP_AMP_CMD_REJECT		0x01
typedef struct __packed {
	uint16_t reason;
} bt_l2cap_amp_cmd_reject;

#define BT_L2CAP_AMP_DISCOVER_REQ	0x02
typedef struct __packed {
	uint16_t size;
	uint16_t features;
} bt_l2cap_amp_discover_req;

#define BT_L2CAP_AMP_DISCOVER_RSP	0x03
typedef struct __packed {
	uint16_t size;
	uint16_t features;
} bt_l2cap_amp_discover_rsp;

#define BT_L2CAP_AMP_CHANGE_NOTIFY		0x04

#define BT_L2CAP_AMP_CHANGE_RESPONSE	0x05

#define BT_L2CAP_AMP_GET_INFO_REQ		0x06
typedef struct __packed {
	uint8_t  ctrlid;
} bt_l2cap_amp_get_info_req;

#define BT_L2CAP_AMP_GET_INFO_RSP		0x07
typedef struct __packed {
	uint8_t  ctrlid;
	uint8_t  status;
	uint32_t total_bw;
	uint32_t max_bw;
	uint32_t min_latency;
	uint16_t pal_cap;
	uint16_t max_assoc_len;
} bt_l2cap_amp_get_info_rsp;

#define BT_L2CAP_AMP_GET_ASSOC_REQ		0x08
typedef struct __packed {
	uint8_t  ctrlid;
} bt_l2cap_amp_get_assoc_req;

#define BT_L2CAP_AMP_GET_ASSOC_RSP		0x09
typedef struct __packed {
	uint8_t  ctrlid;
	uint8_t  status;
} bt_l2cap_amp_get_assoc_rsp;

#define BT_L2CAP_AMP_CREATE_PHY_LINK_REQ	0x0a
typedef struct __packed {
	uint8_t  local_ctrlid;
	uint8_t  remote_ctrlid;
} bt_l2cap_amp_create_phy_link_req;

#define BT_L2CAP_AMP_CREATE_PHY_LINK_RSP	0x0b
typedef struct __packed {
	uint8_t  local_ctrlid;
	uint8_t  remote_ctrlid;
	uint8_t  status;
} bt_l2cap_amp_create_phy_link_rsp;

#define BT_L2CAP_AMP_DISCONN_PHY_LINK_REQ	0x0c
typedef struct __packed {
	uint8_t  local_ctrlid;
	uint8_t  remote_ctrlid;
} bt_l2cap_amp_disconn_phy_link_req;

#define BT_L2CAP_AMP_DISCONN_PHY_LINK_RSP	0x0d
typedef struct __packed {
	uint8_t  local_ctrlid;
	uint8_t  remote_ctrlid;
	uint8_t  status;
} bt_l2cap_amp_disconn_phy_link_rsp;

typedef struct __packed {
	uint8_t  code;
	uint8_t data[];
} bt_l2cap_att_hdr;

#define BT_L2CAP_ATT_ERROR_RESPONSE			0x01
typedef struct __packed {
	uint8_t  request;
	uint16_t handle;
	uint8_t  error;
} bt_l2cap_att_error_response;

#define BT_L2CAP_ATT_EXCHANGE_MTU_REQ		0x02
typedef struct __packed {
	uint16_t mtu;
} bt_l2cap_att_exchange_mtu_req;

#define BT_L2CAP_ATT_EXCHANGE_MTU_RSP		0x03
typedef struct __packed {
	uint16_t mtu;
} bt_l2cap_att_exchange_mtu_rsp;

#define BT_L2CAP_ATT_READ_TYPE_REQ			0x08
typedef struct __packed {
	uint16_t start_handle;
	uint16_t end_handle;
} bt_l2cap_att_read_type_req;

#define BT_L2CAP_ATT_READ_TYPE_RSP			0x09
typedef struct __packed {
	uint8_t  length;
} bt_l2cap_att_read_type_rsp;

#define BT_L2CAP_ATT_READ_REQ				0x0a
typedef struct __packed {
	uint16_t handle;
} bt_l2cap_att_read_req;

#define BT_L2CAP_ATT_READ_RSP				0x0b

#define BT_L2CAP_ATT_READ_GROUP_TYPE_REQ	0x10
typedef struct __packed {
	uint16_t start_handle;
	uint16_t end_handle;
} bt_l2cap_att_read_group_type_req;

#define BT_L2CAP_ATT_READ_GROUP_TYPE_RSP	0x11
typedef struct __packed {
	uint8_t  length;
} bt_l2cap_att_read_group_type_rsp;

#define BT_L2CAP_ATT_HANDLE_VALUE_NOTIFY	0x1b
typedef struct __packed {
	uint16_t handle;
} bt_l2cap_att_handle_value_notify;

#define BT_L2CAP_ATT_HANDLE_VALUE_IND		0x1d
typedef struct __packed {
	uint16_t handle;
} bt_l2cap_att_handle_value_ind;

#define BT_L2CAP_ATT_HANDLE_VALUE_CONF		0x1e

#define BT_L2CAP_ATT_MAX	0x1f

typedef struct __packed {
	uint8_t  code;
	uint8_t data[];
} bt_l2cap_smp_hdr;

#define BT_L2CAP_SMP_PAIRING_REQUEST		0x01
typedef struct __packed {
	uint8_t  io_capa;
	uint8_t  oob_data;
	uint8_t  auth_req;
	uint8_t  max_key_size;
	uint8_t  init_key_dist;
	uint8_t  resp_key_dist;
} bt_l2cap_smp_pairing_request;

#define BT_L2CAP_SMP_PAIRING_RESPONSE	0x02
typedef struct __packed {
	uint8_t  io_capa;
	uint8_t  oob_data;
	uint8_t  auth_req;
	uint8_t  max_key_size;
	uint8_t  init_key_dist;
	uint8_t  resp_key_dist;
} bt_l2cap_smp_pairing_response;

#define BT_L2CAP_SMP_PAIRING_CONFIRM	0x03
typedef struct __packed {
	uint8_t  value[16];
} bt_l2cap_smp_pairing_confirm;

#define BT_L2CAP_SMP_PAIRING_RANDOM		0x04
typedef struct __packed {
	uint8_t  value[16];
} bt_l2cap_smp_pairing_random;

#define BT_L2CAP_SMP_PAIRING_FAILED		0x05
typedef struct __packed {
	uint8_t  reason;
} bt_l2cap_smp_pairing_failed;

#define BT_L2CAP_SMP_ENCRYPT_INFO		0x06
typedef struct __packed {
	uint8_t  ltk[16];
} bt_l2cap_smp_encrypt_info;

#define BT_L2CAP_SMP_CENTRAL_IDENT		0x07
typedef struct __packed {
	uint16_t ediv;
	uint64_t rand;
} bt_l2cap_smp_central_ident;

#define BT_L2CAP_SMP_IDENT_INFO			0x08
typedef struct __packed {
	uint8_t  irk[16];
} bt_l2cap_smp_ident_info;

#define BT_L2CAP_SMP_IDENT_ADDR_INFO	0x09
typedef struct __packed {
	uint8_t  addr_type;
	uint8_t  addr[6];
} bt_l2cap_smp_ident_addr_info;

#define BT_L2CAP_SMP_SIGNING_INFO		0x0a
typedef struct __packed {
	uint8_t  csrk[16];
} bt_l2cap_smp_signing_info;

#define BT_L2CAP_SMP_SECURITY_REQUEST	0x0b
typedef struct __packed {
	uint8_t  auth_req;
} bt_l2cap_smp_security_request;

#define BT_L2CAP_SMP_PUBLIC_KEY			0x0c
typedef struct __packed {
	uint8_t  x[32];
	uint8_t  y[32];
} bt_l2cap_smp_public_key;

#define BT_L2CAP_SMP_DHKEY_CHECK		0x0d
typedef struct __packed {
	uint8_t  e[16];
} bt_l2cap_smp_dhkey_check;

#define BT_L2CAP_SMP_KEYPRESS_NOTIFY	0x0e
typedef struct __packed {
	uint8_t  type;
} bt_l2cap_smp_keypress_notify;

#define BT_L2CAP_SMP_MAX 0x0f

typedef struct __packed {
	uint8_t  pdu;
	uint16_t tid;
	uint16_t plen;
} bt_sdp_hdr;

#define BT_L2CAP_SDP_ERROR_RSP				0x01
typedef struct __packed {
	uint16_t error_code;
} bt_l2cap_sdp_error_rsp;

#define BT_L2CAP_SDP_SERVICE_SEARCH_REQ		0x02
typedef struct __packed {
	
} bt_l2cap_sdp_service_search_req;

#define BT_L2CAP_SDP_SERVICE_SEARCH_RSP		0x03
typedef struct __packed {

} bt_l2cap_sdp_service_search_rsp;

#define BT_l2CAP_SDP_SERVICE_ATTR_REQ		0x04
typedef struct __packed {

} bt_l2cap_sdp_service_attr_req;

#define BT_L2CAP_SDP_SERVICE_ATTR_RSP		0x05
typedef struct __packed {

} bt_l2cap_sdp_service_attr_rsp;

#define BT_L2CAP_SDP_SEARCH_ATTR_REQ		0x06
typedef struct __packed {

} bt_l2cap_sdp_search_attr_req;

#define BT_L2CAP_SDP_SEARCH_ATTR_RSP		0x07
typedef struct __packed {

} bt_l2cap_sdp_search_attr_rsp;

#define SDP_ERR_INVALID_VERSION				0x0001
#define SDP_ERR_INVALID_SERVICE_RECORD		0x0002
#define SDP_ERR_INVALID_REQUEST_SYNTAX		0x0003
#define SDP_ERR_INVALID_PDU_SIZE			0x0004
#define SDP_ERR_INVALID_CONT_STATE			0x0005
#define SDP_ERR_INSUFFICIENT_RESOURCE		0x0006



#endif