#include "bluetooth/hci_format.h"
#include "afl/debug.h"
#include "bluetooth/bluetooth.h"

GArray     *hci_cmds;
GArray     *hci_evts;
GArray     *hci_le_evts;
GArray     *hci_iut_evts;
GArray     *hci_iut_le_evts;
GHashTable *hci_cmd_map;
GHashTable *hci_evt_map;
GHashTable *hci_le_evt_map;
GHashTable *hci_rsp_map;
GHashTable *hci_event_mask_map;
GHashTable *hci_event_mask_page2_map;
GHashTable *hci_le_event_mask_map;

u8 event_mask[] = {
    /* 00 */ BT_HCI_EVT_INQUIRY_COMPLETE,
    /* 01 */ BT_HCI_EVT_INQUIRY_RESULT,
    /* 02 */ BT_HCI_EVT_CONN_COMPLETE,
    /* 03 */ BT_HCI_EVT_CONN_REQUEST,
    /* 04 */ BT_HCI_EVT_DISCONNECT_COMPLETE,
    /* 05 */ BT_HCI_EVT_AUTH_COMPLETE,
    /* 06 */ BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE,
    /* 07 */ BT_HCI_EVT_ENCRYPT_CHANGE,

    /* 08 */ BT_HCI_EVT_CHANGE_CONN_LINK_KEY_COMPLETE,
    /* 09 */ BT_HCI_EVT_LINK_KEY_TYPE_CHANGED,
    /* 10 */ BT_HCI_EVT_REMOTE_FEATURES_COMPLETE,
    /* 11 */ BT_HCI_EVT_REMOTE_VERSION_COMPLETE,
    /* 12 */ BT_HCI_EVT_QOS_SETUP_COMPLETE,
    /* 13 */ 0,
    /* 14 */ 0,
    /* 15 */ BT_HCI_EVT_HARDWARE_ERROR,

    /* 16 */ BT_HCI_EVT_FLUSH_OCCURRED,
    /* 17 */ BT_HCI_EVT_ROLE_CHANGE,
    /* 18 */ 0,
    /* 19 */ BT_HCI_EVT_MODE_CHANGE,
    /* 20 */ BT_HCI_EVT_RETURN_LINK_KEYS,
    /* 21 */ BT_HCI_EVT_PIN_CODE_REQUEST,
    /* 22 */ BT_HCI_EVT_LINK_KEY_REQUEST,
    /* 23 */ BT_HCI_EVT_LINK_KEY_NOTIFY,

    /* 24 */ BT_HCI_EVT_LOOPBACK_COMMAND,
    /* 25 */ BT_HCI_EVT_DATA_BUFFER_OVERFLOW,
    /* 26 */ BT_HCI_EVT_MAX_SLOTS_CHANGE,
    /* 27 */ BT_HCI_EVT_CLOCK_OFFSET_COMPLETE,
    /* 28 */ BT_HCI_EVT_CONN_PKT_TYPE_CHANGED,
    /* 29 */ BT_HCI_EVT_QOS_VIOLATION,
    /* 30 */ BT_HCI_EVT_PSCAN_MODE_CHANGE,
    /* 31 */ BT_HCI_EVT_PSCAN_REP_MODE_CHANGE,

    /* 32 */ BT_HCI_EVT_FLOW_SPEC_COMPLETE,
    /* 33 */ BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI,
    /* 34 */ BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE,
    /* 35 */ 0,
    /* 36 */ 0,
    /* 37 */ 0,
    /* 38 */ 0,
    /* 39 */ 0,

    /* 40 */ 0,
    /* 41 */ 0,
    /* 42 */ 0,
    /* 43 */ BT_HCI_EVT_SYNC_CONN_COMPLETE,
    /* 44 */ BT_HCI_EVT_SYNC_CONN_CHANGED,
    /* 45 */ BT_HCI_EVT_SNIFF_SUBRATING,
    /* 46 */ BT_HCI_EVT_EXT_INQUIRY_RESULT,
    /* 47 */ BT_HCI_EVT_ENCRYPT_KEY_REFRESH_COMPLETE,

    /* 48 */ BT_HCI_EVT_IO_CAPABILITY_REQUEST,
    /* 49 */ BT_HCI_EVT_IO_CAPABILITY_RESPONSE,
    /* 50 */ BT_HCI_EVT_USER_CONFIRM_REQUEST,
    /* 51 */ BT_HCI_EVT_USER_PASSKEY_REQUEST,
    /* 52 */ BT_HCI_EVT_REMOTE_OOB_DATA_REQUEST,
    /* 53 */ BT_HCI_EVT_SIMPLE_PAIRING_COMPLETE,
    /* 54 */ 0,
    /* 55 */ BT_HCI_EVT_LINK_SUPV_TIMEOUT_CHANGED,

    /* 56 */ BT_HCI_EVT_ENHANCED_FLUSH_COMPLETE,
    /* 57 */ 0,
    /* 58 */ BT_HCI_EVT_USER_PASSKEY_NOTIFY,
    /* 59 */ BT_HCI_EVT_KEYPRESS_NOTIFY,
    /* 60 */ BT_HCI_EVT_REMOTE_HOST_FEATURES_NOTIFY,
    /* 61 */ BT_HCI_EVT_LE_META_EVENT,
    /* 62 */ 0,
    /* 63 */ 0};

u8 event_mask_page2[] = {
    /* 00 */ BT_HCI_EVT_PHY_LINK_COMPLETE,
    /* 01 */ BT_HCI_EVT_CHANNEL_SELECTED,
    /* 02 */ BT_HCI_EVT_DISCONN_PHY_LINK_COMPLETE,
    /* 03 */ BT_HCI_EVT_PHY_LINK_LOSS_EARLY_WARNING,
    /* 04 */ BT_HCI_EVT_PHY_LINK_RECOVERY,
    /* 05 */ BT_HCI_EVT_LOGIC_LINK_COMPLETE,
    /* 06 */ BT_HCI_EVT_DISCONN_LOGIC_LINK_COMPLETE,
    /* 07 */ BT_HCI_EVT_FLOW_SPEC_MODIFY_COMPLETE,

    /* 08 */ BT_HCI_EVT_NUM_COMPLETED_DATA_BLOCKS,
    /* 09 */ BT_HCI_EVT_AMP_START_TEST,
    /* 10 */ BT_HCI_EVT_AMP_TEST_END,
    /* 11 */ BT_HCI_EVT_AMP_REC_REPORT,
    /* 12 */ BT_HCI_EVT_SHORT_RANGE_MODE_CHANGE,
    /* 13 */ BT_HCI_EVT_AMP_STATUS_CHANGE,
    /* 14 */ BT_HCI_EVT_TRIGGERED_CLOCK_CAPTURE,
    /* 15 */ BT_HCI_EVT_SYNC_TRAIN_COMPLETE,

    /* 16 */ BT_HCI_EVT_SYNC_TRAIN_RECEIVED,
    /* 17 */ BT_HCI_EVT_PERIPHERAL_BROADCAST_RECEIVE,
    /* 18 */ BT_HCI_EVT_PERIPHERAL_BROADCAST_TIMEOUT,
    /* 19 */ BT_HCI_EVT_TRUNCATED_PAGE_COMPLETE,
    /* 20 */ BT_HCI_EVT_PERIPHERAL_PAGE_RESPONSE_TIMEOUT,
    /* 21 */ BT_HCI_EVT_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE,
    /* 22 */ BT_HCI_EVT_INQUIRY_RESPONSE_NOTIFY,
    /* 23 */ BT_HCI_EVT_AUTH_PAYLOAD_TIMEOUT_EXPIRED,

    /* 24 */ BT_HCI_EVT_SAM_STATUS_CHANGE,
    /* 25 */ BT_HCI_EVT_ENCRYPT_CHANGE_V2,
    /* 26 */ 0,
    /* 27 */ 0,
    /* 28 */ 0,
    /* 29 */ 0,
    /* 30 */ 0,
    /* 31 */ 0,

    /* 32 */ 0,
    /* 33 */ 0,
    /* 34 */ 0,
    /* 35 */ 0,
    /* 36 */ 0,
    /* 37 */ 0,
    /* 38 */ 0,
    /* 39 */ 0,

    /* 40 */ 0,
    /* 41 */ 0,
    /* 42 */ 0,
    /* 43 */ 0,
    /* 44 */ 0,
    /* 45 */ 0,
    /* 46 */ 0,
    /* 47 */ 0,

    /* 48 */ 0,
    /* 49 */ 0,
    /* 50 */ 0,
    /* 51 */ 0,
    /* 52 */ 0,
    /* 53 */ 0,
    /* 54 */ 0,
    /* 55 */ 0,

    /* 56 */ 0,
    /* 57 */ 0,
    /* 58 */ 0,
    /* 59 */ 0,
    /* 60 */ 0,
    /* 61 */ 0,
    /* 62 */ 0,
    /* 63 */ 0};

u8 le_event_mask[] = {
    /* 00 */ BT_HCI_EVT_LE_CONN_COMPLETE,
    /* 01 */ BT_HCI_EVT_LE_ADV_REPORT,
    /* 02 */ BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE,
    /* 03 */ BT_HCI_EVT_LE_REMOTE_FEATURES_COMPLETE,
    /* 04 */ BT_HCI_EVT_LE_LONG_TERM_KEY_REQUEST,
    /* 05 */ BT_HCI_EVT_LE_CONN_PARAM_REQUEST,
    /* 06 */ BT_HCI_EVT_LE_DATA_LENGTH_CHANGE,
    /* 07 */ BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE,

    /* 08 */ BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE,
    /* 09 */ BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE,
    /* 10 */ BT_HCI_EVT_LE_DIRECT_ADV_REPORT,
    /* 11 */ BT_HCI_EVT_LE_PHY_UPDATE_COMPLETE,
    /* 12 */ BT_HCI_EVT_LE_EXT_ADV_REPORT,
    /* 13 */ BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED,
    /* 14 */ BT_HCI_EVT_LE_PA_REPORT,
    /* 15 */ BT_HCI_EVT_LE_PA_SYNC_LOST,

    /* 16 */ BT_HCI_EVT_LE_SCAN_TMOUT,
    /* 17 */ BT_HCI_EVT_LE_ADV_SET_TERM,
    /* 18 */ BT_HCI_EVT_LE_SCAN_REQ_RECEIVED,
    /* 19 */ BT_HCI_EVT_LE_CHAN_SELECT_ALG,
    /* 20 */ BT_HCI_EVT_LE_CONNLESS_IQ_REPORT,
    /* 21 */ BT_HCI_EVT_LE_CONN_IQ_REPORT,
    /* 22 */ BT_HCI_EVT_LE_CTE_REQUEST_FAILED,
    /* 23 */ BT_HCI_EVT_LE_PA_SYNC_TRANS_REC,

    /* 24 */ BT_HCI_EVT_LE_CIS_ESTABLISHED,
    /* 25 */ BT_HCI_EVT_LE_CIS_REQ,
    /* 26 */ BT_HCI_EVT_LE_BIG_COMPLETE,
    /* 27 */ BT_HCI_EVT_LE_BIG_TERMINATE,
    /* 28 */ BT_HCI_EVT_LE_BIG_SYNC_ESTABILISHED,
    /* 29 */ BT_HCI_EVT_LE_BIG_SYNC_LOST,
    /* 30 */ BT_HCI_EVT_LE_REQ_PEER_SCA_COMPLETE,
    /* 31 */ BT_HCI_EVT_LE_PATH_LOSS_THRESH,

    /* 32 */ BT_HCI_EVT_LE_TRANSMIT_POWER_REPORT,
    /* 33 */ BT_HCI_EVT_LE_BIG_INFO_ADV_REPORT,
    /* 34 */ BT_HCI_EVT_LE_SUBRATE_CHANGE,
    /* 35 */ BT_HCI_EVT_LE_PA_SYNC_ESTABLISHED_V2,
    /* 36 */ BT_HCI_EVT_LE_PA_REPORT_V2,
    /* 37 */ BT_HCI_EVT_LE_PA_SYNC_TRANS_REC_V2,
    /* 38 */ BT_HCI_EVT_LE_PA_SUBEVENT_REQ,
    /* 39 */ BT_HCI_EVT_LE_PA_RESP_REPORT,

    /* 40 */ BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE_V2,

    [41 ... 63] = 0,

};

static inline hci_cmd_format_t *new_hci_cmd_format(
    uint16_t opcode, uint32_t size, uint32_t rsp_size, int offset1, int offset2,
    int offset3, int offset4, int offset5) {
  hci_cmd_format_t *fmt;
  fmt = (hci_cmd_format_t *)malloc(sizeof(hci_cmd_format_t));
  fmt->opcode = opcode;
  fmt->size = size;
  fmt->rsp_size = rsp_size;
  fmt->bd_addr_offset = offset1;
  fmt->handle_offset = offset2;
  fmt->rsp_status_offset = offset3;
  fmt->rsp_bd_addr_offset = offset4;
  fmt->rsp_handle_offset = offset5;
  return fmt;
}

static inline hci_evt_format_t *new_hci_evt_format(bool le, uint16_t opcode,
                                                   uint32_t size, int offset1,
                                                   int offset2, int offset3) {
  hci_evt_format_t *fmt;
  fmt = (hci_evt_format_t *)malloc(sizeof(hci_evt_format_t));
  fmt->le = le;
  fmt->opcode = opcode;
  fmt->size = size;
  fmt->status_offset = offset1;
  fmt->bd_addr_offset = offset2;
  fmt->handle_offset = offset3;
  return fmt;
}

#define DEF_CMD(_opcode, _size, _rsp_size, _o1, _o2, _o3, _o4, _o5)        \
  do {                                                                     \
    hci_cmd_format_t *_fmt = new_hci_cmd_format(_opcode, _size, _rsp_size, \
                                                _o1, _o2, _o3, _o4, _o5);  \
    g_hash_table_insert(hci_cmd_map, GINT_TO_POINTER(_fmt->opcode), _fmt); \
    g_array_append_val(hci_cmds, _fmt);                                    \
  } while (0);

#define DEF_EVT(_opcode, _size, _o1, _o2, _o3)                             \
  do {                                                                     \
    hci_evt_format_t *_fmt =                                               \
        new_hci_evt_format(false, _opcode, _size, _o1, _o2, _o3);          \
    g_hash_table_insert(hci_evt_map, GINT_TO_POINTER(_fmt->opcode), _fmt); \
    g_array_append_val(hci_evts, _fmt);                                    \
  } while (0);

#define DEF_LE_EVT(_opcode, _size, _o1, _o2, _o3)                             \
  do {                                                                        \
    hci_evt_format_t *_fmt =                                                  \
        new_hci_evt_format(true, _opcode, _size, _o1, _o2, _o3);              \
    g_hash_table_insert(hci_le_evt_map, GINT_TO_POINTER(_fmt->opcode), _fmt); \
    g_array_append_val(hci_le_evts, _fmt);                                    \
  } while (0);

#define DEF_RSP(_cmd, _evt)                                            \
  do {                                                                 \
    hci_evt_format_t *_rsp_fmt = get_hci_evt(_evt);                    \
    g_hash_table_insert(hci_rsp_map, GINT_TO_POINTER(_cmd), _rsp_fmt); \
  } while (0);

#define DEF_LE_RSP(_cmd, _evt)                                         \
  do {                                                                 \
    hci_evt_format_t *_rsp_fmt = get_hci_le_evt(_evt);                 \
    g_hash_table_insert(hci_rsp_map, GINT_TO_POINTER(_cmd), _rsp_fmt); \
  } while (0);

void __ctor init_hci_formats(void) {
  hci_cmds = g_array_new(true, true, sizeof(hci_cmd_format_t *));
  hci_evts = g_array_new(true, true, sizeof(hci_evt_format_t *));
  hci_le_evts = g_array_new(true, true, sizeof(hci_evt_format_t *));
  hci_iut_evts = g_array_new(true, true, sizeof(hci_evt_format_t *));
  hci_iut_le_evts = g_array_new(true, true, sizeof(hci_evt_format_t *));
  hci_cmd_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  hci_evt_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  hci_rsp_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  hci_le_evt_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  hci_event_mask_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  hci_event_mask_page2_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  hci_le_event_mask_map = g_hash_table_new(g_direct_hash, g_direct_equal);

  DEF_CMD(0x401, 5, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x402, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x403, 9, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x404, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x405, 13, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x406, 3, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x408, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x409, 7, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x40a, 7, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x40b, 22, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x40c, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x40d, 23, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x40e, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x40f, 4, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x411, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x413, 3, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x415, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x417, 1, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x419, 10, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x41a, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x41b, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x41c, 3, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x41d, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x41f, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x420, 2, 8, -1, 0, 0, -1, 1);
  DEF_CMD(0x428, 17, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x429, 21, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x42a, 7, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x42b, 9, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x42c, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x42d, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x42e, 10, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x42f, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x430, 38, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x433, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x434, 7, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x43d, 59, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x43e, 63, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x43f, 9, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x440, 6, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x441, 11, 4, -1, -1, 0, -1, -1);
  DEF_CMD(0x442, 34, 8, 1, -1, 0, 1, -1);
  DEF_CMD(0x443, 0, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x444, 12, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x445, 70, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0x801, 6, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x803, 10, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x804, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x807, 20, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x809, 2, 4, -1, 0, 0, -1, 1);
  DEF_CMD(0x80b, 7, 0, 0, -1, -1, -1, -1);
  DEF_CMD(0x80c, 2, 5, -1, 0, 0, -1, 1);
  DEF_CMD(0x80d, 4, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x80e, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0x80f, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x810, 21, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x811, 8, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0xc01, 8, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc03, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc05, 3, 0, -1, -1, 0, -1, -1);
  DEF_CMD(0xc08, 2, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0xc09, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc0a, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc0d, 7, 5, 0, -1, 0, -1, -1);
  DEF_CMD(0xc12, 7, 3, 0, -1, 0, -1, -1);
  DEF_CMD(0xc13, 248, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc14, 0, 249, -1, -1, 0, -1, -1);
  DEF_CMD(0xc15, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc16, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc17, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc18, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc19, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc1a, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc1b, 0, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0xc1c, 4, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc1d, 0, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0xc1e, 4, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc1f, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc20, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc23, 0, 4, -1, -1, 0, -1, -1);
  DEF_CMD(0xc24, 3, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc25, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc26, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc27, 2, 5, -1, 0, 0, -1, 1);
  DEF_CMD(0xc28, 4, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0xc29, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc2a, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc2b, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc2c, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc2d, 3, 4, -1, 0, 0, -1, 1);
  DEF_CMD(0xc2e, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc2f, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc31, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc33, 7, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc36, 2, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0xc37, 4, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc38, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc3f, 10, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc42, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc43, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc44, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc45, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc46, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc47, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc48, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc49, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc51, 0, 242, -1, -1, 0, -1, -1);
  DEF_CMD(0xc52, 241, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc53, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0xc55, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc56, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc57, 0, 33, -1, -1, 0, -1, -1);
  DEF_CMD(0xc58, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc59, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc60, 7, 7, 0, -1, 0, 1, -1);
  DEF_CMD(0xc5a, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc5b, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc5f, 3, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0xc63, 8, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc66, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc67, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc68, 3, 6, -1, 0, 0, -1, 1);
  DEF_CMD(0xc6c, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc6d, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc6e, 10, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc70, 30, 33, -1, -1, 0, -1, -1);
  DEF_CMD(0xc71, 9, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc74, 1, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc75, 1, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc77, 0, 8, -1, -1, 0, -1, -1);
  DEF_CMD(0xc78, 9, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc79, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0xc7a, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc7b, 2, 5, -1, 0, 0, -1, 1);
  DEF_CMD(0xc7c, 4, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0xc7d, 0, 65, -1, -1, 0, -1, -1);
  DEF_CMD(0xc7e, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc7f, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc80, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0xc81, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc82, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0xc84, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x1001, 0, 9, -1, -1, 0, -1, -1);
  DEF_CMD(0x1002, 0, 65, -1, -1, 0, -1, -1);
  DEF_CMD(0x1003, 0, 9, -1, -1, 0, -1, -1);
  DEF_CMD(0x1004, 1, 11, -1, -1, 0, -1, -1);
  DEF_CMD(0x1005, 0, 8, -1, -1, 0, -1, -1);
  DEF_CMD(0x1009, 0, 7, -1, -1, 0, 1, -1);
  DEF_CMD(0x100a, 0, 7, -1, -1, 0, -1, -1);
  DEF_CMD(0x100c, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0x1401, 2, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0x1402, 2, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0x1403, 2, 4, -1, -1, 0, -1, -1);
  DEF_CMD(0x1405, 2, 4, -1, -1, 0, -1, -1);
  DEF_CMD(0x1406, 2, 14, -1, 0, 0, -1, 1);
  DEF_CMD(0x1407, 3, 8, -1, 0, 0, -1, 2);
  DEF_CMD(0x1408, 2, 4, -1, 0, 0, -1, 1);
  DEF_CMD(0x140d, 6, 1, -1, 0, 0, -1, -1);
  DEF_CMD(0x1801, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x1802, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x1803, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x1804, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x180a, 4, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2001, 8, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2002, 0, 4, -1, -1, 0, -1, -1);
  DEF_CMD(0x2003, 0, 9, -1, -1, 0, -1, -1);
  DEF_CMD(0x2005, 6, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2006, 15, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2007, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x2008, 32, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2009, 32, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x200a, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x200b, 7, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x200c, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x200d, 25, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x200e, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x200f, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x2010, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2011, 7, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2012, 7, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2013, 14, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x2014, 5, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2015, 2, 8, -1, 0, 0, -1, 1);
  DEF_CMD(0x2016, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x2017, 32, 17, -1, -1, 0, -1, -1);
  DEF_CMD(0x2018, 0, 9, -1, -1, 0, -1, -1);
  DEF_CMD(0x2019, 28, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x201a, 18, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x201b, 2, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x201c, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x201f, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0x2020, 14, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2021, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2022, 6, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2023, 0, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0x2024, 4, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2025, 0, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x2027, 39, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2028, 7, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2029, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x202a, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x202b, 7, 7, -1, -1, 0, -1, -1);
  DEF_CMD(0x202c, 7, 7, -1, -1, 0, -1, -1);
  DEF_CMD(0x202d, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x202e, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x202f, 0, 9, -1, -1, 0, -1, -1);
  DEF_CMD(0x2030, 2, 5, -1, 0, 0, -1, 1);
  DEF_CMD(0x2031, 3, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2032, 7, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x2035, 7, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x203a, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0x203b, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x203c, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x203d, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2040, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2041, 4, 0, -1, -1, 0, -1, -1);
  DEF_CMD(0x2042, 6, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2044, 14, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x2045, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2046, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2047, 8, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2048, 8, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2049, 0, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x204a, 0, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x204b, 0, 3, -1, -1, 0, -1, -1);
  DEF_CMD(0x204c, 0, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0x204d, 4, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x204e, 8, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2052, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2056, 7, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2057, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2058, 0, 5, -1, -1, 0, -1, -1);
  DEF_CMD(0x2059, 3, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x205a, 6, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x205b, 5, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x205c, 8, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x205d, 6, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x205f, 1, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2061, 2, 12, -1, 0, 0, -1, 1);
  DEF_CMD(0x2065, 1, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x2066, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x2067, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2068, 31, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x2069, 36, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x206a, 2, 0, -1, -1, -1, -1, -1);
  DEF_CMD(0x206c, 1, 2, -1, -1, 0, -1, -1);
  DEF_CMD(0x206d, 2, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x206f, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2070, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2071, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2072, 2, 15, -1, 0, 0, -1, 1);
  DEF_CMD(0x2073, 2, 15, -1, 0, 0, -1, 1);
  DEF_CMD(0x2074, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x2075, 2, 31, -1, 0, 0, -1, 1);
  DEF_CMD(0x2076, 3, 6, -1, 0, 0, -1, 1);
  DEF_CMD(0x2077, 3, 0, -1, 0, -1, -1, -1);
  DEF_CMD(0x2078, 8, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x2079, 3, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x207a, 4, 3, -1, 0, 0, -1, 1);
  DEF_CMD(0x207c, 2, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x207d, 10, 1, -1, -1, 0, -1, -1);
  DEF_CMD(0x207e, 12, 0, -1, 0, -1, -1, -1);
  DEF_EVT(0x1, 1, 0, -1, -1);
  DEF_EVT(0x3, 11, 0, 3, 1);
  DEF_EVT(0x4, 10, -1, 0, -1);
  DEF_EVT(0x5, 4, 0, -1, 1);
  DEF_EVT(0x6, 3, 0, -1, 1);
  DEF_EVT(0x7, 255, 0, 1, -1);
  DEF_EVT(0x8, 4, 0, 1, -1);
  DEF_EVT(0x9, 3, 0, -1, 1);
  DEF_EVT(0xa, 4, 0, -1, 1);
  DEF_EVT(0xb, 11, 0, -1, 1);
  DEF_EVT(0xc, 8, 0, -1, 1);
  DEF_EVT(0xd, 21, 0, -1, 1);
  DEF_EVT(0xe, 3, -1, -1, -1);
  DEF_EVT(0xf, 4, 0, -1, -1);
  DEF_EVT(0x10, 1, -1, -1, -1);
  DEF_EVT(0x11, 2, -1, -1, -1);
  DEF_EVT(0x12, 8, 0, 1, -1);
  DEF_EVT(0x14, 6, 0, -1, 1);
  DEF_EVT(0x16, 6, -1, 0, -1);
  DEF_EVT(0x17, 6, -1, 0, -1);
  DEF_EVT(0x18, 23, -1, 0, -1);
  DEF_EVT(0x19, 0, -1, -1, -1);
  DEF_EVT(0x1a, 1, -1, -1, -1);
  DEF_EVT(0x1b, 3, -1, -1, 0);
  DEF_EVT(0x1c, 5, 0, -1, 1);
  DEF_EVT(0x1d, 5, 0, -1, 1);
  DEF_EVT(0x1e, 2, -1, -1, -1);
  DEF_EVT(0x20, 7, -1, 0, -1);
  DEF_EVT(0x21, 22, 0, -1, 1);
  DEF_EVT(0x23, 13, 0, -1, 1);
  DEF_EVT(0x2c, 17, 0, 3, 1);
  DEF_EVT(0x2d, 9, 0, -1, 1);
  DEF_EVT(0x2e, 11, 0, -1, 1);
  DEF_EVT(0x2f, 255, -1, 1, -1);
  DEF_EVT(0x30, 3, 0, -1, 1);
  DEF_EVT(0x31, 6, -1, 0, -1);
  DEF_EVT(0x32, 9, -1, 0, -1);
  DEF_EVT(0x33, 10, -1, 0, -1);
  DEF_EVT(0x34, 6, -1, 0, -1);
  DEF_EVT(0x35, 6, -1, 0, -1);
  DEF_EVT(0x36, 7, 0, 1, -1);
  DEF_EVT(0x38, 4, -1, -1, 0);
  DEF_EVT(0x39, 2, -1, -1, -1);
  DEF_EVT(0x3b, 10, -1, 0, -1);
  DEF_EVT(0x3c, 7, -1, 0, -1);
  DEF_EVT(0x3d, 14, -1, 0, -1);
  DEF_EVT(0x4e, 9, -1, -1, 0);
  DEF_EVT(0x4f, 1, 0, -1, -1);
  DEF_EVT(0x50, 29, 0, 1, -1);
  DEF_EVT(0x52, 7, -1, 0, -1);
  DEF_EVT(0x53, 7, 0, 1, -1);
  DEF_EVT(0x54, 0, -1, -1, -1);
  DEF_EVT(0x55, 10, -1, -1, -1);
  DEF_EVT(0x56, 4, -1, -1, -1);
  DEF_EVT(0x57, 2, -1, -1, 0);
  DEF_EVT(0x58, 8, -1, -1, 0);
  DEF_LE_EVT(1, 19, 1, -1, 2);
  DEF_LE_EVT(4, 12, 1, -1, 2);
  DEF_LE_EVT(5, 13, -1, -1, 1);
  DEF_LE_EVT(6, 11, -1, -1, 1);
  DEF_LE_EVT(7, 11, -1, -1, 1);
  DEF_LE_EVT(8, 66, 1, -1, -1);
  DEF_LE_EVT(9, 34, 1, -1, -1);
  DEF_LE_EVT(41, 34, 1, -1, 2);
  DEF_LE_EVT(12, 6, 1, -1, 2);
  DEF_LE_EVT(36, 20, 1, -1, -1);
  DEF_LE_EVT(16, 3, -1, -1, -1);
  DEF_LE_EVT(17, 1, -1, -1, -1);
  DEF_LE_EVT(18, 6, 1, -1, 3);
  DEF_LE_EVT(19, 9, -1, -1, -1);
  DEF_LE_EVT(20, 4, -1, -1, 1);
  DEF_LE_EVT(23, 4, 1, -1, 2);
  DEF_LE_EVT(38, 24, 1, -1, 2);
  DEF_LE_EVT(25, 29, 1, -1, 2);
  DEF_LE_EVT(26, 7, -1, -1, -1);
  DEF_LE_EVT(27, 21, 1, -1, -1);
  DEF_LE_EVT(28, 3, -1, -1, -1);
  DEF_LE_EVT(30, 3, -1, -1, -1);
  DEF_LE_EVT(31, 5, 1, -1, 2);
  DEF_LE_EVT(32, 5, -1, -1, 1);
  DEF_LE_EVT(33, 9, 1, -1, 2);
  DEF_LE_EVT(34, 20, -1, -1, -1);
  DEF_LE_EVT(35, 12, 1, -1, 2);
  DEF_LE_EVT(39, 4, -1, -1, -1);

  DEF_LE_RSP(BT_HCI_CMD_LE_READ_LOCAL_PK256,
             BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE);
}

hci_cmd_format_t *get_hci_cmd(uint16_t opcode) {
  return (hci_cmd_format_t *)g_hash_table_lookup(hci_cmd_map,
                                                 GUINT_TO_POINTER(opcode));
}

hci_evt_format_t *get_hci_evt(uint8_t opcode) {
  return (hci_evt_format_t *)g_hash_table_lookup(hci_evt_map,
                                                 GUINT_TO_POINTER(opcode));
}

hci_evt_format_t *get_hci_le_evt(uint8_t opcode) {
  return (hci_evt_format_t *)g_hash_table_lookup(hci_le_evt_map,
                                                 GUINT_TO_POINTER(opcode));
}

hci_evt_format_t *get_hci_cmd_rsp(uint16_t opcode) {
  return (hci_evt_format_t *)g_hash_table_lookup(hci_rsp_map,
                                                 GUINT_TO_POINTER(opcode));
}

hci_cmd_format_t *get_hci_cmd_by_index(uint32_t index) {
  if (index >= hci_cmds->len) return NULL;
  return g_array_index(hci_cmds, hci_cmd_format_t *, index);
}

hci_evt_format_t *get_hci_evt_by_index(uint32_t index) {
  if (index >= hci_evts->len) return NULL;
  return g_array_index(hci_evts, hci_evt_format_t *, index);
}

hci_evt_format_t *get_hci_le_evt_by_index(uint32_t index) {
  if (index >= hci_le_evts->len) return NULL;
  return g_array_index(hci_le_evts, hci_evt_format_t *, index);
}

void update_event_mask_map(void) {
  for (int i = 0; i < sizeof(event_mask); ++i) {
    if (event_mask[i]) {
      g_hash_table_insert(hci_event_mask_map, GUINT_TO_POINTER(event_mask[i]),
                          GUINT_TO_POINTER(1));
    }
  }
}

void update_event_mask_page2_map(void) {
  for (int i = 0; i < sizeof(event_mask_page2); ++i) {
    if (event_mask_page2[i]) {
      g_hash_table_insert(hci_event_mask_page2_map,
                          GUINT_TO_POINTER(event_mask_page2[i]),
                          GUINT_TO_POINTER(1));
    }
  }
}

void update_le_event_mask_map(void) {
  for (int i = 0; i < sizeof(le_event_mask); ++i) {
    if (le_event_mask[i]) {
      g_hash_table_insert(hci_le_event_mask_map,
                          GUINT_TO_POINTER(le_event_mask[i]),
                          GUINT_TO_POINTER(1));
    }
  }
}

void add_hci_iut_evt(uint8_t opcode) {
  hci_evt_format_t *fmt = get_hci_evt(opcode);
  if (!fmt) { FATAL("Unhandled event: 0x%x", opcode); }
  if (g_hash_table_lookup(hci_event_mask_map, GUINT_TO_POINTER(opcode)) ||
      g_hash_table_lookup(hci_event_mask_page2_map, GUINT_TO_POINTER(opcode))) {
    g_array_append_val(hci_iut_evts, fmt);
  }
}

void add_hci_iut_le_evt(uint8_t opcode) {
  hci_evt_format_t *fmt = get_hci_le_evt(opcode);
  if (!fmt) { FATAL("Unhandled LE Event: 0x%x", opcode); }
  if (g_hash_table_lookup(hci_le_event_mask_map, GUINT_TO_POINTER(opcode))) {
    g_array_append_val(hci_iut_le_evts, fmt);
  }
}

uint32_t hci_cmd_cnt(void) {
  return hci_cmds->len;
}

uint32_t hci_evt_cnt(void) {
  return hci_evts->len;
}

uint32_t hci_le_evt_cnt(void) {
  return hci_le_evts->len;
}

uint32_t hci_iut_evt_cnt(void) {
  return hci_iut_evts->len;
}

uint32_t hci_iut_le_evt_cnt(void) {
  return hci_iut_le_evts->len;
}

GArray     *hci_nodes;
GHashTable *hci_node_map;

void __ctor init_hci_nodes(void) {
  hci_nodes = g_array_new(true, true, sizeof(hci_node_t));
  hci_node_map = g_hash_table_new(g_direct_hash, g_direct_equal);
}

uint32_t hci_node(uint8_t *message) {
  uint8_t    type = message[0];
  hci_node_t result;
  memset(&result, 0, sizeof(result));
  if (type == BT_H4_CMD_PKT) {
    bt_hci_cmd_hdr *header = (bt_hci_cmd_hdr *)&message[1];
    result.opcode1 = type;
    result.opcode2 = header->opcode;
    result.opcode3 = 0;
    result.opcode4 = 0;

  } else if (type == BT_H4_EVT_PKT) {
    bt_hci_evt_hdr *header = (bt_hci_evt_hdr *)&message[1];
    if (header->evt == BT_HCI_EVT_LE_META_EVENT) {
      result.opcode1 = type;
      result.opcode2 = BT_HCI_EVT_LE_META_EVENT;
      result.opcode3 = header->params[0];
      result.opcode4 = 0;
    } else {
      result.opcode1 = type;
      result.opcode2 = 0;
      result.opcode3 = header->evt;
      result.opcode4 = 0;
    }

  } else if (type == BT_H4_ACL_PKT) {
    bt_hci_acl_hdr *acl_header = (bt_hci_acl_hdr *)&message[1];
    bt_l2cap_hdr   *l2cap_header = (bt_l2cap_hdr *)acl_header->data;
    result.opcode1 = BT_H4_ACL_PKT;
    result.opcode2 = l2cap_header->cid;
    result.opcode3 = l2cap_header->data[0];
    result.opcode4 = 0;

  } else if (type == BT_TMOUT) {
    result.opcode1 = BT_TMOUT;
    result.opcode2 = 0;
    result.opcode3 = 0;
    result.opcode4 = 0;
  }

  gpointer key = GINT_TO_POINTER((*(uint64_t *)&result));
  gpointer value = g_hash_table_lookup(hci_node_map, key);
  if (!value) {
    guint size = g_hash_table_size(hci_node_map);
    g_hash_table_insert(hci_node_map, key, GUINT_TO_POINTER(size + 1));
    return size + 1;
  } else {
    return GPOINTER_TO_UINT(value);
  }
}

uint32_t hci_edge(uint32_t src, uint32_t dest) {
  return (src << 8) | dest;
}
