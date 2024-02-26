#include "afl/afl-fuzz-bluetooth.h"
#include "afl/afl-fuzz.h"
#include "afl/afl-mutations.h"
#include "bluetooth/bluetooth.h"
#include "bluetooth/hci_format.h"
#include "panda/buzzer.h"
#include "qemu-common.h"

#include <string.h>

static u8 ident;
const u8 *bd_addr_local = "local";
const u8 *bd_addr_remote = "remote";

void emit_message(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                  u32 i) {
  message_t *message = q->messages[i];
  memcpy(afl->fsrv.shmem_fuzz, message, message->size + sizeof(message_t));
  // qemu_hexdump(message, stdout, "Fuzz Send", message->size + sizeof(message_t));
  send_ctrl_step_one();
}

void append_cmd_status(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                       u16 opcode, u8 status, u8 use_new) {
  APPEND_EVENT_COMMON(BT_HCI_EVT_CMD_STATUS, bt_hci_evt_cmd_status,
                      sizeof(bt_hci_evt_cmd_status), use_new);
  evt_params->ncmd = 10;
  evt_params->opcode = opcode;
  evt_params->status = status;
}

void append_cmd_complete(afl_state_t *afl, bt_state_t *bt,
                         struct queue_entry *q, u16 opcode, void *payload,
                         u32 size, u8 use_new) {
  APPEND_EVENT_COMMON(BT_HCI_EVT_CMD_COMPLETE, bt_hci_evt_cmd_complete,
                      sizeof(bt_hci_evt_cmd_complete) + size, use_new);
  evt_params->ncmd = 10;
  evt_params->opcode = opcode;
  memcpy(evt_params->params, payload, size);
}

void append_cmd_complete_success(afl_state_t *afl, bt_state_t *bt,
                                 struct queue_entry *q, u16 opcode,
                                 u8 use_new) {
  u8 status = BT_HCI_ERR_SUCCESS;
  append_cmd_complete(afl, bt, q, opcode, &status, sizeof(status), use_new);
}

void append_le_event(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                     u8 opcode, void *payload, u32 size, u8 use_new) {
  APPEND_LE_EVENT_COMMON(opcode, u8, size, use_new);
  memcpy(evt_params, payload, size);
}

void append_discon_complete(afl_state_t *afl, bt_state_t *bt,
                            struct queue_entry *q, u16 handle, u8 use_new) {
  APPEND_EVENT_COMMON(BT_HCI_EVT_DISCONNECT_COMPLETE,
                      bt_hci_evt_disconnect_complete,
                      sizeof(bt_hci_evt_disconnect_complete), use_new);
  evt_params->status = BT_HCI_ERR_SUCCESS;
  evt_params->handle = handle;
  evt_params->reason = rand_below(afl, UINT8_MAX);
}

void append_conn_request(afl_state_t *afl, bt_state_t *bt,
                         struct queue_entry *q, u16 handle, u8 use_new) {
  APPEND_EVENT_COMMON(BT_HCI_EVT_CONN_REQUEST, bt_hci_evt_conn_request,
                      sizeof(bt_hci_evt_conn_request), use_new);
  evt_params->link_type = 1;
  memcpy(evt_params->bdaddr, bd_addr_remote, 6);
  rand_bytes(afl, evt_params->dev_class, sizeof(evt_params->dev_class));
}

void append_conn_complete(afl_state_t *afl, bt_state_t *bt,
                          struct queue_entry *q, u16 handle, u8 status,
                          u8 use_new) {
  if (handle == BREDR_HANDLE) {
    APPEND_EVENT_COMMON(BT_HCI_EVT_CONN_COMPLETE, bt_hci_evt_conn_complete,
                        sizeof(bt_hci_evt_conn_complete), use_new);
    memcpy(evt_params->bdaddr, bd_addr_remote, 6);
    evt_params->handle = handle;
    evt_params->status = status;
    evt_params->encr_mode = rand_below(afl, 3);
    evt_params->link_type = rand_below(afl, 3);

  } else {
    APPEND_LE_EVENT_COMMON(BT_HCI_EVT_LE_CONN_COMPLETE,
                           bt_hci_evt_le_conn_complete,
                           sizeof(bt_hci_evt_le_conn_complete), use_new);
    rand_bytes(afl, evt_params, sizeof(*evt_params));
    memcpy(evt_params->peer_addr, bd_addr_remote, 6);
    evt_params->handle = handle;
    evt_params->status = status;
    evt_params->peer_addr_type = rand_below(afl, 3);
    evt_params->role = rand_below(afl, 3);
  }
}

void append_num_completed_packets(afl_state_t *afl, bt_state_t *bt,
                                  struct queue_entry *q, u16 handle,
                                  u8 use_new) {
  APPEND_EVENT_COMMON(BT_HCI_EVT_NUM_COMPLETED_PACKETS,
                      bt_hci_evt_num_completed_packets,
                      sizeof(bt_hci_evt_num_completed_packets), use_new);
  evt_params->num_handles = 1;
  evt_params->handle = handle;
  evt_params->count = 1;
}

u8 is_link_change_event(message_t *message) {
  if (message->data[0] == BT_H4_EVT_PKT) {
    bt_hci_evt_hdr *evt = (bt_hci_evt_hdr *)&message->data[1];
    if (evt->evt == BT_HCI_EVT_CONN_COMPLETE ||
        evt->evt == BT_HCI_EVT_DISCONNECT_COMPLETE ||
        evt->evt == BT_HCI_EVT_CONN_REQUEST)
      return true;
    if (evt->evt == BT_HCI_EVT_LE_META_EVENT) {
      if (evt->params[0] == BT_HCI_EVT_LE_CONN_COMPLETE) { return true; }
    }
  }
  return 0;
}

void append_link_change_event(afl_state_t *afl, bt_state_t *bt,
                              struct queue_entry *q, u16 handle, u8 use_new) {
  switch (bt->conns[handle].state) {
    case RCVD_CREATE_CONN:
      append_conn_complete(afl, bt, q, handle, BT_HCI_ERR_SUCCESS, use_new);
      break;

    case RCVD_ACCEPT_CONN:
      append_conn_complete(afl, bt, q, handle, BT_HCI_ERR_SUCCESS, use_new);
      break;

    case RCVD_REJECT_CONN:
      append_conn_complete(afl, bt, q, handle, rand_below(afl, UINT8_MAX) + 1,
                           use_new);
      break;

    case RCVD_CONN_CANCEL:
      append_conn_complete(afl, bt, q, handle, BT_HCI_ERR_UNKNOWN_CONN_ID,
                           use_new);
      break;

    case RCVD_DISCON:
      append_discon_complete(afl, bt, q, handle, use_new);
      break;

    case SENT_CONN_REQ:
    case CONNECTED:
      append_discon_complete(afl, bt, q, handle, use_new);
      break;

    case DISCONNECTED:
      if (handle == LE_HANDLE) {
        append_conn_complete(afl, bt, q, handle, BT_HCI_ERR_SUCCESS, use_new);
      } else {
        append_conn_request(afl, bt, q, handle, use_new);
      }
      break;

    default:
      FATAL("");
  }
}

void append_event_from_format(afl_state_t *afl, struct queue_entry *q,
                              hci_evt_format_t *fmt, u8 use_new) {
  u8 *bd_addrs[] = {bd_addr_local, bd_addr_remote};
  u16 handle;
  u8  opcode;
  u32 len;

  if (fmt->le) {
    opcode = BT_HCI_EVT_LE_META_EVENT;
    handle = LE_HANDLE;

  } else {
    opcode = fmt->opcode;
    handle = BREDR_HANDLE;
  }

  APPEND_EVENT_COMMON(opcode, u8, fmt->size, use_new);

  if (fmt->le) { evt_params[0] = fmt->opcode; }

  len = afl_mutate(afl, evt_params, fmt->size, afl->stage_cur_val, false,
             !afl->fuzz_mode, NULL, 0, 512);

  if (fmt->bd_addr_offset != -1) {
    memcpy(&evt_params[fmt->bd_addr_offset], bd_addrs[rand_below(afl, 2)], 6);
  }

  if (fmt->handle_offset != -1) {
    *(u16 *)&evt_params[fmt->handle_offset] = handle;
  }

  if (fmt->status_offset != -1) {
    evt_params[fmt->status_offset] = BT_HCI_ERR_SUCCESS;
  }
}

void append_event(afl_state_t *afl, struct queue_entry *q, u8 opcode,
                  void *payload, u32 size, u8 use_new) {
  APPEND_EVENT_COMMON(opcode, u8, size, use_new);
  memcpy(evt_params, payload, size);
}

void append_event_random(afl_state_t *afl, bt_state_t *bt,
                         struct queue_entry *q, u8 use_new) {
  u32               r;
  u32               evt_cnt = hci_evt_cnt();
  u32               le_evt_cnt = hci_le_evt_cnt();
  hci_evt_format_t *fmt;

  if (!buzzer->disable_bredr && !buzzer->disable_le) {
    r = rand_below(afl, 2);
    if (r == 0) {
      r = rand_below(afl, evt_cnt);
      fmt = get_hci_evt_by_index(r);
    } else {
      r = rand_below(afl, le_evt_cnt);
      fmt = get_hci_le_evt_by_index(r);
    }

  } else if (!buzzer->disable_bredr) {
    r = rand_below(afl, evt_cnt);
    fmt = get_hci_evt_by_index(r);

  } else {
    r = rand_below(afl, le_evt_cnt);
    fmt = get_hci_le_evt_by_index(r);
  }

  append_event_from_format(afl, q, fmt, use_new);
}

void append_l2cap_sig(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                      u16 handle, u16 cid, u8 ident, u8 code, void *payload,
                      u32 size, u8 use_new) {
  APPEND_L2CAP_COMMON(handle, cid, bt_l2cap_sig_hdr,
                      sizeof(bt_l2cap_hdr) + size, use_new);
  l2cap_params->code = code;
  l2cap_params->ident = ident;
  l2cap_params->len = size;
  memcpy(l2cap_params->data, payload, size);

  append_num_completed_packets(afl, bt, q, handle, 0);
}

void append_l2cap_sig_random(afl_state_t *afl, bt_state_t *bt,
                             struct queue_entry *q, u8 use_new) {
  static u8 sigs[] = {
      BT_L2CAP_PDU_CMD_REJECT,        BT_L2CAP_PDU_CONN_REQ,
      BT_L2CAP_PDU_CONN_RSP,          BT_L2CAP_PDU_CONFIG_REQ,
      BT_L2CAP_PDU_CONFIG_RSP,        BT_L2CAP_PDU_DISCONN_REQ,
      BT_L2CAP_PDU_DISCONN_RSP,       BT_L2CAP_PDU_ECHO_REQ,
      BT_L2CAP_PDU_ECHO_RSP,          BT_L2CAP_PDU_INFO_REQ,
      BT_L2CAP_PDU_INFO_RSP,          BT_L2CAP_PDU_CREATE_CHAN_REQ,
      BT_L2CAP_PDU_CREATE_CHAN_RSP,   BT_L2CAP_PDU_MOVE_CHAN_REQ,
      BT_L2CAP_PDU_MOVE_CHAN_RSP,     BT_L2CAP_PDU_MOVE_CHAN_CFM,
      BT_L2CAP_PDU_MOVE_CHAN_CFM_RSP, BT_L2CAP_PDU_CONN_PARAM_REQ,
      BT_L2CAP_PDU_CONN_PARAM_RSP,    BT_L2CAP_PDU_LE_CONN_REQ,
      BT_L2CAP_PDU_LE_CONN_RSP,       BT_L2CAP_PDU_LE_FLOWCTL_CREDS,
      BT_L2CAP_PDU_ECRED_CONN_REQ,    BT_L2CAP_PDU_ECRED_CONN_RSP,
      BT_L2CAP_PDU_ECRED_RECONF_REQ,  BT_L2CAP_PDU_ECRED_RECONF_RSP,
  };

  static u8 le_sigs[] = {
      BT_L2CAP_PDU_CMD_REJECT,       BT_L2CAP_PDU_DISCONN_REQ,
      BT_L2CAP_PDU_DISCONN_RSP,      BT_L2CAP_PDU_CONN_PARAM_REQ,
      BT_L2CAP_PDU_CONN_PARAM_RSP,   BT_L2CAP_PDU_LE_CONN_REQ,
      BT_L2CAP_PDU_LE_CONN_RSP,      BT_L2CAP_PDU_LE_FLOWCTL_CREDS,
      BT_L2CAP_PDU_ECRED_CONN_REQ,   BT_L2CAP_PDU_ECRED_CONN_RSP,
      BT_L2CAP_PDU_ECRED_RECONF_REQ, BT_L2CAP_PDU_ECRED_RECONF_RSP,
  };

  u16 handle = bt_state_select_handle(afl, bt);
  u32 payload_size = 64, payload_max_size = 256;
  u8 *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_max_size);
  memset(payload, 0, payload_max_size);
  payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val,
                            false, !afl->fuzz_mode, NULL, 0, payload_max_size);

  if (handle == LE_HANDLE) {
    append_l2cap_sig(afl, bt, q, handle, BT_L2CAP_CID_SIG_LE, ++ident,
                     le_sigs[rand_below(afl, sizeof(le_sigs))], payload,
                     payload_size, use_new);
  } else {
    append_l2cap_sig(afl, bt, q, handle, BT_L2CAP_CID_SIG, ++ident,
                     sigs[rand_below(afl, sizeof(sigs))], payload, payload_size,
                     use_new);
  }
}

void append_smp(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                u16 handle, u16 cid, u8 code, void *payload, u32 size,
                u8 use_new) {
  APPEND_L2CAP_COMMON(handle, cid, bt_l2cap_smp_hdr,
                      sizeof(bt_l2cap_smp_hdr) + size, use_new);
  l2cap_params->code = code;
  memcpy(l2cap_params->data, payload, size);
  append_num_completed_packets(afl, bt, q, handle, 0);
}

void append_smp_random(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                       u8 use_new) {
  static u8 smps[] = {
      BT_L2CAP_SMP_PAIRING_REQUEST,  BT_L2CAP_SMP_PAIRING_RESPONSE,
      BT_L2CAP_SMP_PAIRING_CONFIRM,  BT_L2CAP_SMP_PAIRING_RANDOM,
      BT_L2CAP_SMP_PAIRING_FAILED,   BT_L2CAP_SMP_ENCRYPT_INFO,
      BT_L2CAP_SMP_CENTRAL_IDENT,    BT_L2CAP_SMP_IDENT_INFO,
      BT_L2CAP_SMP_IDENT_ADDR_INFO,  BT_L2CAP_SMP_SIGNING_INFO,
      BT_L2CAP_SMP_SECURITY_REQUEST, BT_L2CAP_SMP_PUBLIC_KEY,
      BT_L2CAP_SMP_DHKEY_CHECK,      BT_L2CAP_SMP_KEYPRESS_NOTIFY};

  static u8 bredr_smps[] = {
      BT_L2CAP_SMP_PAIRING_REQUEST, BT_L2CAP_SMP_PAIRING_RESPONSE,
      BT_L2CAP_SMP_PAIRING_FAILED,  BT_L2CAP_SMP_IDENT_INFO,
      BT_L2CAP_SMP_IDENT_ADDR_INFO, BT_L2CAP_SMP_SIGNING_INFO};

  u16 handle = bt_state_select_handle(afl, bt);
  u32 payload_size = 32, payload_max_size = 256;
  u8 *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_max_size);

  memset(payload, 0, payload_max_size);
  payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val,
                            false, !afl->fuzz_mode, NULL, 0, payload_max_size);

  if (handle == LE_HANDLE) {
    append_smp(afl, bt, q, handle, BT_L2CAP_CID_SMP,
               smps[rand_below(afl, sizeof(smps))], payload, payload_size,
               use_new);

  } else {
    append_smp(afl, bt, q, handle, BT_L2CAP_CID_SMP_BREDR,
               bredr_smps[rand_below(afl, sizeof(bredr_smps))], payload,
               payload_size, use_new);
  }
}

void append_att(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                u16 handle, u8 code, void *payload, u32 size, u8 use_new) {
  APPEND_L2CAP_COMMON(handle, BT_L2CAP_CID_ATT, bt_l2cap_att_hdr,
                      sizeof(bt_l2cap_att_hdr) + size, use_new);
  l2cap_params->code = code;
  memcpy(l2cap_params->data, payload, size);
  append_num_completed_packets(afl, bt, q, handle, 0);
}

void append_att_random(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                       u8 use_new) {
  static u8 atts[] = {
      BT_L2CAP_ATT_ERROR_RESPONSE,
      BT_L2CAP_ATT_EXCHANGE_MTU_REQ,
      BT_L2CAP_ATT_EXCHANGE_MTU_RSP,
      BT_L2CAP_ATT_READ_TYPE_REQ,
      BT_L2CAP_ATT_READ_TYPE_RSP,
      BT_L2CAP_ATT_READ_REQ,
      BT_L2CAP_ATT_READ_RSP,
      BT_L2CAP_ATT_READ_GROUP_TYPE_REQ,
      BT_L2CAP_ATT_READ_GROUP_TYPE_RSP,
      BT_L2CAP_ATT_HANDLE_VALUE_NOTIFY,
      BT_L2CAP_ATT_HANDLE_VALUE_IND,
      BT_L2CAP_ATT_HANDLE_VALUE_CONF,
  };

  u32 payload_size = 64, payload_max_size = 512;
  u8 *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_max_size);
  memset(payload, 0, payload_max_size);
  payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val,
                            false, !afl->fuzz_mode, NULL, 0, payload_max_size);

  append_att(afl, bt, q, LE_HANDLE, atts[rand_below(afl, sizeof(atts))],
             payload, payload_size, use_new);
}

void append_message_random(afl_state_t *afl, bt_state_t *bt,
                           struct queue_entry *q, u8 use_new) {
  enum {
    FUZZ_LINK_LE = 0,  // prob0
    FUZZ_LINK_BREDR,   // prob1
    FUZZ_EVENT,        // prob2 * 0.2
    FUZZ_L2CAP,        // prob2 * 0.4
    FUZZ_SMP,          //
    FUZZ_ATT           // prob2 * 0.2
  };

  u8     action;
  double prob, prob0 = 0, prob1 = 0, prob2 = 0;

  if (!buzzer->disable_le) prob0 = hci_conn_change_state_prob(bt->le_conn);

  if (!buzzer->disable_bredr)
    prob1 = hci_conn_change_state_prob(bt->bredr_conn);

  prob2 = 1 - prob0 - prob1;

  double probs[] = {prob0, prob1, prob2 * 0.3, prob2 * 0.4, 0, prob2 * 0.3};
  action = prob_select(afl, probs, sizeof(probs) / sizeof(double));

  switch (action) {
    case FUZZ_LINK_LE:
      append_link_change_event(afl, bt, q, LE_HANDLE, use_new);
      return;

    case FUZZ_LINK_BREDR:
      append_link_change_event(afl, bt, q, BREDR_HANDLE, use_new);
      return;

    case FUZZ_EVENT:
      append_event_random(afl, bt, q, use_new);
      return;

    case FUZZ_L2CAP:
      append_l2cap_sig_random(afl, bt, q, use_new);
      return;

    case FUZZ_SMP:
      append_smp_random(afl, bt, q, use_new);
      return;

    case FUZZ_ATT:
      append_att_random(afl, bt, q, use_new);
      return;

    default:
      FATAL("");
  }
}

void queue_entry_load(struct queue_entry *q) {
  message_t *message;
  FILE *     f = fopen((char *)q->fname, "r");

  ck_fread(f, &q->max_message_cnt, sizeof(u32), q->fname);

  q->messages = afl_realloc((void **)&q->messages,
                            q->max_message_cnt * sizeof(message_t *));

  if (unlikely(!f)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

  for (int i = 0; i < q->max_message_cnt; ++i) {
    message = afl_realloc((void **)&q->messages[i], sizeof(message_t));
    ck_fread(f, message, sizeof(message_t), q->fname);
    message = afl_realloc((void **)&q->messages[i],
                          message->size + sizeof(message_t));
    ck_fread(f, message->data, message->size, q->fname);
  }

  q->message_cnt = q->max_message_cnt;

  q->loaded = 1;

  fclose(f);
}

u32 queue_entry_save(struct queue_entry *q, char *fn) {
  u32        len = 0, message_cnt;
  message_t *message;
  FILE *     f = fopen(fn, "w");

  if (unlikely(!f)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

  if (q->mother) {
    message_cnt = q->mother->message_cnt + q->message_cnt;
  } else {
    message_cnt = q->message_cnt;
  }

  ck_fwrite(f, &message_cnt, sizeof(u32), fn);

  if (q->mother) {
    for (int i = 0; i < q->mother->message_cnt; ++i) {
      message = (message_t *)q->mother->messages[i];
      ck_fwrite(f, message, message->size + sizeof(message_t), fn);
      len += (message->size + sizeof(message_t));
    }
  }

  for (int i = 0; i < q->message_cnt; ++i) {
    message = (message_t *)q->messages[i];
    ck_fwrite(f, message, message->size + sizeof(message_t), fn);
    len += (message->size + sizeof(message_t));
  }

  fclose(f);

  return len;
}

void queue_entry_free_messages(struct queue_entry *q) {
  for (int i = 0; i < q->max_message_cnt; ++i) {
    afl_free(q->messages[i]);
  }
  afl_free(q->messages);
}

void *queue_entry_append_message(struct queue_entry *q, u32 size, u8 use_new) {
  if (use_new) {
    afl_realloc((void **)&q->messages,
                (++q->message_cnt) * sizeof(message_t *));
    afl_realloc((void **)&q->messages[q->message_cnt - 1],
                size + sizeof(message_t));

    if (q->message_cnt > q->max_message_cnt) {
      q->max_message_cnt = q->message_cnt;
    }

    q->messages[q->message_cnt - 1]->type = FUZZ_SEND;
    q->messages[q->message_cnt - 1]->size = size;
    return q->messages[q->message_cnt - 1]->data;

  } else {
    u32        orig_size;
    message_t *message;
    message = q->messages[q->message_cnt - 1];
    orig_size = message->size;
    afl_realloc((void **)&q->messages[q->message_cnt - 1],
                sizeof(message_t) + orig_size + size);
    message->size += size;
    return &message->data[orig_size];
  }
}

message_t* queue_entry_message_tail(struct queue_entry* q) {
  return q->messages[q->message_cnt - 1];
}

void queue_entry_append_message_recv(afl_state_t* afl, struct queue_entry* q) {
  message_t *message, *message_new;
  message = (message_t*)afl->fsrv.shmem_fuzz;
  message_new = queue_entry_append_message(q, message->size, 1);
  memcpy(&message_new[-1], message, message->size + sizeof(message_t));
}

void queue_entry_pop_message(struct queue_entry *q) {
  q->message_cnt--;
}

void queue_entry_clear_messages(struct queue_entry *q) {
  q->message_cnt = 0;
}

u32 queue_entry_exec_us(struct queue_entry *q) {
  u32        us = 0;
  message_t *message;

  if (q->mother) {
    for (int i = 0; i < q->mother->message_cnt; ++i) {
      message = q->mother->messages[i];
      if (message->type != FUZZ_SEND) { us += message->time; }
    }
  }

  for (int i = 0; i < q->message_cnt; ++i) {
    message = q->messages[i];
    if (message->type != FUZZ_SEND) { us += message->time; }
  }
  return us;
}

void trace_message_bits(afl_state_t *afl, struct queue_entry *q) {
  u32 src, dest, edge;
  for (int i = 0; i < q->message_cnt; ++i) {
    message_t *message = q->messages[i];
    if (message->type == FUZZ_SEND) {
      src = hci_node(message->data);
    } else {
      dest = hci_node(message->data);
      edge = hci_edge(src, dest);
      afl->fsrv.trace_bits[edge]++;
    }
  }
}

/*
static void extract_events(void) {
    auto result = (AnalyzeResult*)buzzer_state.message_buffer;

    do {
        if (events_map.empty())
            break;

        uint8_t event_buf[1 + sizeof(bt_hci_evt_hdr) + 255];
        send_ctrl(CMD_START_RECORD);
        pids.push_back(recv_stat());

        HCIEvtFormat* event = events_map.begin()->second;
        OKF("%02x", event->opcode_);
        send_event(NULL, event->opcode_, event_buf, event->size_); // Send
testing event recv_stat();                        // Wait for the next packet
(or timeout) send_ctrl(CMD_EXIT);                // Exit now recv_stat(); //
Wait for successful exit

        result->terminate = true;
        result->count = 0;
        send_ctrl(CMD_EXTRACT_EVENTS);      // Start analysis process
        pids.push_back(recv_stat());        // Recv analysis pid
        recv_stat();                        // Wait for analysis to complete

        for (uint32_t i = 0; i < result->count; i++) {
            iut_events_set.insert(result->data[i]);
            events_map.erase(result->data[i]);
        }
        events_map.erase(event->opcode_);

    } while (!result->terminate);

    iut_events.insert(iut_events.begin(), iut_events_set.begin(),
iut_events_set.end());

    OKF("Event extraction complete, iut accepted events are:\n");
    for (uint8_t opcode : iut_events_set)
        std::cout << std::hex << (uint32_t)opcode << std::endl;

    do {
        if (events_map.empty())
            break;

        uint8_t event_buf[1 + sizeof(bt_hci_evt_hdr) + 255];
        send_ctrl(CMD_START_RECORD);
        pids.push_back(recv_stat());

        HCIEvtFormat* event = events_map.begin()->second;
        uint8_t opcode = event->opcode_ & 0xFF;
        send_le_event(NULL, opcode, event_buf, event->size_ - 1); // Send
testing event recv_stat();                        // Wait for the next packet
(or timeout) send_ctrl(CMD_EXIT);                // Exit now recv_stat(); //
Wait for successful exit

        result->terminate = true;
        result->count = 0;
        send_ctrl(CMD_EXTRACT_LE_EVENTS);   // Start analysis process
        pids.push_back(recv_stat());        // Recv analysis pid
        recv_stat();                        // Wait for analysis to complete

        for (uint32_t i = 0; i < result->count; i++) {
            iut_le_events_set.insert(MAKE_LE(result->data[i]));
            events_map.erase(MAKE_LE(result->data[i]));
        }

        for (uint8_t opcode : iut_le_events_set)
            std::cout << std::hex << (uint32_t)opcode << std::endl;

        events_map.erase(event->opcode_);

    } while (!result->terminate);

    OKF("Event extraction complete, iut accepted le events are:\n");
    for (uint8_t opcode : iut_le_events_set)
        std::cout << std::hex << (uint32_t)opcode << std::endl;
}
*/

void dump_messages(struct queue_entry *q) {
  char *prefix;
  for (int i = 0; i < q->message_cnt; ++i) {
    message_t *message = q->messages[i];
    if (message->type == FUZZ_SEND) {
      prefix = "send";
    } else {
      prefix = "recv";
    }
    // qemu_hexdump(message->data, stdout, prefix, message->size);
  }
}

u8 handle_acl(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
              bt_hci_acl_hdr *acl, u32 max_size, u32 *size, u8 use_new) {
  if (unlikely(acl->dlen + sizeof(*acl) > max_size)) return 2;

  u16           handle = acl->handle & 0xFFF;
  u32           payload_size = 128;
  u8 *          payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_size);
  bt_l2cap_hdr *l2cap = (bt_l2cap_hdr *)acl->data;

  if (unlikely(acl->dlen != l2cap->len + sizeof(*l2cap))) return 2;

  *size = acl->dlen + sizeof(*acl);

  bt_state_update_from_acl(bt, acl);

  if (l2cap->cid == BT_L2CAP_CID_SIG_LE || l2cap->cid == BT_L2CAP_CID_SIG) {
    bt_l2cap_sig_hdr *sig;
    sig = (bt_l2cap_sig_hdr *)l2cap->data;

    if (unlikely(l2cap->len != sig->len + sizeof(*sig))) return 2;

    memset(payload, 0, payload_size);
    afl_mutate(afl, payload, payload_size, afl->stage_cur_val, 0,
               !afl->fuzz_mode, NULL, 0, 256);

    switch (sig->code) {
      case BT_L2CAP_PDU_CONN_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_CONN_RSP, payload, payload_size, use_new);
        return 1;

      case BT_L2CAP_PDU_CONFIG_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_CONFIG_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_DISCONN_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_DISCONN_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_ECHO_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_ECHO_RSP, payload, payload_size, use_new);
        return 1;

      case BT_L2CAP_PDU_INFO_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_INFO_RSP, payload, payload_size, use_new);
        return 1;

      case BT_L2CAP_PDU_CREATE_CHAN_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_CREATE_CHAN_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_MOVE_CHAN_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_MOVE_CHAN_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_MOVE_CHAN_CFM:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_MOVE_CHAN_CFM_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_CONN_PARAM_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_CONN_PARAM_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_LE_CONN_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_LE_CONN_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_ECRED_CONN_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_ECRED_CONN_RSP, payload, payload_size,
                         use_new);
        return 1;

      case BT_L2CAP_PDU_ECRED_RECONF_REQ:
        append_l2cap_sig(afl, bt, q, handle, l2cap->cid, sig->ident,
                         BT_L2CAP_PDU_ECRED_RECONF_RSP, payload, payload_size,
                         use_new);
        return 1;
    }

  } else if (l2cap->cid == BT_L2CAP_CID_ATT) {
    bt_l2cap_att_hdr *att;
    att = (bt_l2cap_att_hdr *)l2cap->data;
    switch (att->code) {
      case BT_L2CAP_ATT_EXCHANGE_MTU_REQ:
        append_att(afl, bt, q, handle, BT_L2CAP_ATT_EXCHANGE_MTU_RSP, payload,
                   payload_size, use_new);
        return 1;

      case BT_L2CAP_ATT_READ_TYPE_REQ:
        append_att(afl, bt, q, handle, BT_L2CAP_ATT_READ_TYPE_RSP, payload,
                   payload_size, use_new);
        return 1;

      case BT_L2CAP_ATT_READ_REQ:
        append_att(afl, bt, q, handle, BT_L2CAP_ATT_READ_RSP, payload,
                   payload_size, use_new);
        return 1;

      case BT_L2CAP_ATT_READ_GROUP_TYPE_REQ:
        append_att(afl, bt, q, handle, BT_L2CAP_ATT_READ_GROUP_TYPE_REQ,
                   payload, payload_size, use_new);
        return 1;

      case BT_L2CAP_ATT_HANDLE_VALUE_IND:
        append_att(afl, bt, q, handle, BT_L2CAP_ATT_HANDLE_VALUE_CONF, payload,
                   payload_size, use_new);
        return 1;
    }
  }
  return 0;
}

u8 handle_command(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q,
                  bt_hci_cmd_hdr *cmd, u32 max_size, u32 *size, u8 use_new) {
  if (cmd->plen + sizeof(*cmd) > max_size) { return 2; }

  hci_cmd_format_t *cmd_fmt;
  u8 *              bd_addrs[] = {bd_addr_local, bd_addr_remote};
  u8 *              rsp;

  *size = cmd->plen + sizeof(*cmd);

  if (cmd->opcode == BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS) return 0;

  cmd_fmt = get_hci_cmd(cmd->opcode);

  if (!cmd_fmt) { FATAL("Command 0x%04x not found", cmd->opcode); }

  bt_state_update_from_cmd(bt, cmd);

  if (cmd_fmt->rsp_size) {
    // We should send a command_complete_event
    rsp = afl_realloc(AFL_BUF_PARAM(out_scratch), cmd_fmt->rsp_size);
    memset(rsp, 0xFF, cmd_fmt->rsp_size);
    afl_mutate(afl, rsp, cmd_fmt->rsp_size, afl->stage_cur_val, false,
               !afl->fuzz_mode, NULL, 0, 256);

    if (cmd_fmt->rsp_bd_addr_offset != -1) {
      strncpy((char *)&rsp[cmd_fmt->rsp_bd_addr_offset], "local", 6);
    }
    if (cmd_fmt->rsp_status_offset != -1) {
      rsp[cmd_fmt->rsp_status_offset] = BT_HCI_ERR_SUCCESS;
    }
    append_cmd_complete(afl, bt, q, cmd->opcode, rsp, cmd_fmt->rsp_size,
                        use_new);

  } else {
    // We should send a command_status_event
    append_cmd_status(afl, bt, q, cmd->opcode, BT_HCI_ERR_SUCCESS, use_new);
  }

  hci_evt_format_t *rsp_fmt = get_hci_cmd_rsp(cmd_fmt->opcode);
  if (rsp_fmt) {
    rsp = afl_realloc(AFL_BUF_PARAM(out_scratch), rsp_fmt->size);
    memset(rsp, 0xFF, rsp_fmt->size);
    afl_mutate(afl, rsp, rsp_fmt->size, afl->stage_cur_val, false,
               !afl->fuzz_mode, NULL, 0, 256);

    if (rsp_fmt->status_offset != -1) {
      rsp[rsp_fmt->status_offset] = BT_HCI_ERR_SUCCESS;
    }

    if (rsp_fmt->bd_addr_offset != -1) {
      if (cmd_fmt->bd_addr_offset != -1) {
        memcpy(&rsp[rsp_fmt->bd_addr_offset],
               &cmd->params[cmd_fmt->bd_addr_offset], 6);
      } else {
        memcpy(&rsp[rsp_fmt->bd_addr_offset], bd_addrs[rand_below(afl, 2)], 6);
      }
    }

    if (rsp_fmt->handle_offset != -1) {
      if (cmd_fmt->handle_offset != -1) {
        u16 handle = *(u16 *)&cmd->params[cmd_fmt->handle_offset];
        *(u16 *)&rsp[rsp_fmt->handle_offset] = handle;

      } else {
        if (rsp_fmt->le) {
          *(u16 *)&rsp[rsp_fmt->handle_offset] = LE_HANDLE;
        } else {
          *(u16 *)&rsp[rsp_fmt->handle_offset] = BREDR_HANDLE;
        }
      }
    }

    if (rsp_fmt->le) {
      rsp[0] = rsp_fmt->opcode;
      append_event(afl, q, BT_HCI_EVT_LE_META_EVENT, rsp, rsp_fmt->size, 0);

    } else {
      append_event(afl, q, rsp_fmt->opcode, rsp, rsp_fmt->size, 0);
    }
  }

  return 1;
}

// Return 0: no message appended
// Return 1: new message appended
// Return 2: crash occured
u8 handle_message(afl_state_t *afl, bt_state_t *bt, struct queue_entry *q, message_t* message) {
  u8 *       ptr;
  u8 *       end;
  u32        size, messages = 0;
  u8         use_new = 1, new_appended = 0;

  if (likely(!message)) {
    message = (message_t*)afl->fsrv.shmem_fuzz;
  }

  ptr = message->data;
  end = &message->data[message->size];

  // qemu_hexdump(message->data, stdout, "Fuzz Recv", message->size);

  while (ptr < end) {
    if (*ptr == BT_H4_CMD_PKT) {
      bt_hci_cmd_hdr *cmd = (bt_hci_cmd_hdr *)(++ptr);
      new_appended = handle_command(afl, bt, q, cmd, end - ptr, &size, use_new);
      ptr += size;

    } else if (*ptr == BT_H4_ACL_PKT) {
      bt_hci_acl_hdr *acl = (bt_hci_acl_hdr *)(++ptr);
      new_appended = handle_acl(afl, bt, q, acl, end - ptr, &size, use_new);
      ptr += size;

    }

    if (likely(new_appended == 1)) {
      use_new = 0;

    } else if (unlikely(new_appended == 2)) {
      return 2;
    }
  }

  return new_appended;
}

void handle_iut_initialization(afl_state_t *afl) {
  int                 status;
  message_t *message = (message_t *)afl->fsrv.shmem_fuzz;
  struct queue_entry *q = afl->queue_tmp;

  q->mother = NULL;
  afl->fsrv.trace_bits = buzzer->shmem_trace = buzzer->shmem_trace_mother;

  afl->stage_name = "IUTInit";
  afl->stage_short = "IUTInit";
  afl->stage_cur_val = 16;
  // afl->queue_cur = q;

  for (int i = 0; i < IUT_INIT_TRY_MAX; ++i) {
    memset(afl->fsrv.trace_bits, 0, MAP_SIZE);
    queue_entry_clear_messages(q);
    bt_state_reset(&afl->bt_state);

    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

    append_cmd_complete_success(afl, &afl->bt_state, q, BT_HCI_CMD_RESET, 1);
    emit_message(afl, &afl->bt_state, q, q->message_cnt - 1);

    while (!afl->stop_soon) {
      status = recv_stat();
      queue_entry_append_message_recv(afl, q);

      if (status == STAT_RUN_TMOUT) {
        OKF("IUT initialized");
        afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());
        common_fuzz_stuff(afl, q, FSRV_RUN_OK);
        break;

      } else if (status == STAT_RUN_OK) {
        if (handle_message(afl, &afl->bt_state, q, message)) {
          afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());
          common_fuzz_stuff(afl, q, FSRV_RUN_CRASH);
          break;
        }
        emit_message(afl, &afl->bt_state, q, q->message_cnt - 1);

      } else if (status == STAT_RUN_CRASH) {
        WARNF("IUT Crashes during initialization");
        afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());
        common_fuzz_stuff(afl, q, FSRV_RUN_CRASH);
        break;
      }
    }
  }

  // Saturate the bitmap
  // if (!afl->stop_soon) {
  //     int n;
  //     hci_evt_format_t* evt;
  //     send_ctrl_create_fsrv();

  //     n = hci_evt_cnt();
  //     for (int i = 0; i < n; ++i) {

  //         memset(afl->fsrv.trace_bits, 0, afl->fsrv.map_size);
  //         MEM_BARRIER();

  //         ACTF("%d", i);
  //         evt = get_hci_evt_by_index(i);
  //         send_ctrl_start_normal();
  //         ACTF("fsrv");
  //         afl_fsrv_push_child(&afl->fsrv, recv_stat());
  //         send_event_dummy(afl, evt);
  //         recv_stat();
  //         send_ctrl_exit();
  //         ACTF("exit");
  //         afl_fsrv_pop_child(&afl->fsrv);

  //         uint64_t cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size,
  //         HASH_CONST); ACTF("cksum %llx", cksum);
  //         classify_counts(&afl->fsrv);
  //         if (has_new_bits(afl, afl->virgin_bits) == 2) {
  //             OKF("IUT Evt: %02x", evt->opcode);
  //         }
  //     }

  //     n = hci_le_evt_cnt();
  //     for (int i = 0; i < n; ++i) {
  //         evt = get_hci_le_evt_by_index(i);
  //         afl_fsrv_push_child(&afl->fsrv, recv_stat());
  //         send_le_event_dummy(afl, evt);
  //         send_ctrl_exit();
  //         afl_fsrv_pop_child(&afl->fsrv);

  //         classify_counts(&afl->fsrv);
  //         if (has_new_bits(afl, afl->virgin_bits) == 2) {
  //             OKF("IUT LE Evt: %02x", evt->opcode);
  //         }
  //     }
  // }`
}

void bt_state_init(bt_state_t *bt) {
  bt->le_conn = &bt->conns[LE_HANDLE];
  bt->bredr_conn = &bt->conns[BREDR_HANDLE];
  bt->le_conn->handle = LE_HANDLE;
  bt->bredr_conn->handle = BREDR_HANDLE;
  bt->le_conn->packets = bt->bredr_conn->packets = 0;
  bt->le_conn->state = bt->bredr_conn->state = DISCONNECTED;
}

void bt_state_reset(bt_state_t *bt) {
  bt->le_conn->packets = bt->bredr_conn->packets = 0;
  bt->le_conn->state = bt->bredr_conn->state = DISCONNECTED;
}

void bt_state_copy(bt_state_t *dest, bt_state_t *src) {
  memcpy(dest->conns, src->conns, sizeof(dest->conns));
}

void bt_state_update_from_acl(bt_state_t *bt, bt_hci_acl_hdr *acl) {
  u16 handle = acl->handle & 0xFFF;
  if (handle == LE_HANDLE) {
    bt->le_conn->packets++;

  } else if (handle == BREDR_HANDLE) {
    bt->bredr_conn->packets++;
  }
}

void bt_state_update_from_evt(bt_state_t *bt, bt_hci_evt_hdr *evt) {
  switch (evt->evt) {
    case BT_HCI_EVT_CONN_REQUEST:
      hci_conn_set_state(bt->bredr_conn, SENT_CONN_REQ);
      break;

    case BT_HCI_EVT_CONN_COMPLETE:
      bt_hci_evt_conn_complete *cc;
      cc = (bt_hci_evt_conn_complete *)evt->params;
      if (cc->status == BT_HCI_ERR_SUCCESS)
        hci_conn_set_state(bt->bredr_conn, CONNECTED);
      else
        hci_conn_set_state(bt->bredr_conn, DISCONNECTED);
      break;

    case BT_HCI_EVT_DISCONNECT_COMPLETE:
      bt_hci_evt_disconnect_complete *disc;
      disc = (bt_hci_evt_disconnect_complete *)evt->params;
      hci_conn_set_state(&bt->conns[disc->handle], DISCONNECTED);
      break;

    case BT_HCI_EVT_LE_META_EVENT:
      if (evt->params[0] == BT_HCI_EVT_LE_CONN_COMPLETE) {
        if (evt->params[0] == BT_HCI_ERR_SUCCESS)
          hci_conn_set_state(bt->le_conn, CONNECTED);
        else
          hci_conn_set_state(bt->le_conn, DISCONNECTED);
      }

    default:
      break;
  }
}

void bt_state_update_from_cmd(bt_state_t *bt, bt_hci_cmd_hdr *cmd) {
  switch (cmd->opcode) {
    case BT_HCI_CMD_CREATE_CONN:
      hci_conn_set_state(bt->bredr_conn, RCVD_CREATE_CONN);
      break;

    case BT_HCI_CMD_LE_CREATE_CONN:
      hci_conn_set_state(bt->le_conn, RCVD_CREATE_CONN);
      break;

    case BT_HCI_CMD_CREATE_CONN_CANCEL:
      hci_conn_set_state(bt->bredr_conn, RCVD_CONN_CANCEL);
      break;

    case BT_HCI_CMD_LE_CREATE_CONN_CANCEL:
      hci_conn_set_state(bt->le_conn, RCVD_CONN_CANCEL);
      break;

    case BT_HCI_CMD_ACCEPT_CONN_REQUEST:
      hci_conn_set_state(bt->bredr_conn, RCVD_ACCEPT_CONN);
      break;

    case BT_HCI_CMD_REJECT_CONN_REQUEST:
      hci_conn_set_state(bt->bredr_conn, RCVD_REJECT_CONN);
      break;

    case BT_HCI_CMD_DISCONNECT:
      bt_hci_cmd_disconnect *disc = (bt_hci_cmd_disconnect *)(cmd->params);
      hci_conn_set_state(&bt->conns[disc->handle], RCVD_DISCON);
      break;

    default:
      break;
  }
}

void bt_state_update(bt_state_t *bt, message_t *message) {
  if (message->type == FUZZ_SEND) {
    if (message->data[0] == BT_H4_CMD_PKT) {
      bt_state_update_from_cmd(bt, (bt_hci_cmd_hdr *)&message->data[1]);

    } else if (message->data[0] == BT_H4_ACL_PKT) {
      bt_state_update_from_acl(bt, (bt_hci_acl_hdr *)&message->data[1]);
    }

  } else if (message->type == FUZZ_RECV_OK) {
    if (message->data[0] == BT_H4_EVT_PKT) {
      bt_state_update_from_evt(bt, (bt_hci_evt_hdr *)&message->data[1]);

    } else if (message->data[0] == BT_H4_ACL_PKT) {
      bt_state_update_from_acl(bt, (bt_hci_acl_hdr *)&message->data[1]);
    }
  }
}

u16 bt_state_select_handle(afl_state_t *afl, bt_state_t *bt) {
  if (bt->le_conn->state == CONNECTED && bt->bredr_conn->state == CONNECTED) {
    return rand_below(afl, 2);

  } else if (bt->le_conn->state == CONNECTED) {
    return LE_HANDLE;

  } else if (bt->bredr_conn->state == CONNECTED) {
    return BREDR_HANDLE;
  } else {
    return 0xFF;
  }
}

double hci_conn_change_state_prob(hci_conn_t *conn) {
  if (conn->handle == LE_HANDLE && buzzer->disable_le) return 0;
  if (conn->handle == BREDR_HANDLE && buzzer->disable_bredr) return 0;

  switch (conn->state) {
    case RCVD_CREATE_CONN:
    case RCVD_ACCEPT_CONN:
    case RCVD_REJECT_CONN:
    case RCVD_DISCON:
    case DISCONNECTED:
      return 0.3;
    case SENT_CONN_REQ:
      return 0.05;
    case CONNECTED:
      return conn->packets * 0.01;
    default:
      FATAL("Invalid connection state: %d", conn->state);
      return 0;
  }
}

void hci_conn_set_state(hci_conn_t *conn, u8 state) {
  conn->state = state;
}

void bt_state_simulate(bt_state_t *bt, struct queue_entry *q) {
  message_t *message;
  for (int i = 0; i < q->message_cnt; ++i) {
    message = (message_t *)q->messages[i];
    bt_state_update(bt, message);
  }
}

// Given a message sequence, execute that sequence,
// create a forkserver spinning on the state after the sequence
u8 perform_dry_run(afl_state_t *afl, struct queue_entry *q) {
  int        stat;
  message_t *message;
  bt_state_t* bt = &afl->bt_state;

  afl->fsrv.trace_bits = buzzer->shmem_trace = buzzer->shmem_trace_mother;
  memset(afl->fsrv.trace_bits, 0, afl->fsrv.map_size);

  bt_state_reset(&q->bt_state);

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  for (int i = 0; i < q->message_cnt; ++i) {
    message = q->messages[i];
    if (message->type == FUZZ_SEND) {
      //qemu_hexdump(message, stdout, "fuzz send",
      //              message->size + sizeof(*message));
      memcpy(afl->fsrv.shmem_fuzz, message, message->size + sizeof(*message));
      send_ctrl_step_one();
      recv_stat();
    }

    bt_state_update(&q->bt_state, message);
    // } else if (message->type == FUZZ_RECV_OK) {
    //   stat = recv_stat();

    //   if (message->size != message_recv->size ||
    //       memcmp(message->data, message_recv->data, message->size)) {
    //     printf("\n\n\n\n\n\n\n\n\n\n%d\n", stat);
    //     qemu_hexdump(message, stdout, "expected",
    //                  message->size + sizeof(*message));
    //     qemu_hexdump(message_recv, stdout, "real",
    //                  message_recv->size + sizeof(*message));
    //     FATAL("%d", stat);
    //     return 0;
    //   }

    // } else if (message->type == FUZZ_RECV_TMOUT) {
    //   stat = recv_stat();
    //   if (stat != STAT_RUN_TMOUT) {
    //     FATAL("B");
    //     return 0;
    //   }

    // } else {
    //   FATAL("C");
    //   return 0;
    // }
  }

  send_ctrl_create_fsrv();
  afl->fsrv.trace_bits = buzzer->shmem_trace = buzzer->shmem_trace_child;
  return 1;
}

void pklg_write_header(FILE *f, u32 tv_sec, u32 tv_us, u8 packet_type,
                       u8 fuzz_send, uint16_t len) {
  pklg_header_t header;
  header.size = SWAP32(sizeof(header) - 4 + len);
  header.tv_sec = SWAP32(tv_sec);
  header.tv_usec = SWAP32(tv_us);

  switch (packet_type) {
    case BT_H4_CMD_PKT:
      header.type = 0x00;
      break;
    case BT_H4_ACL_PKT:
      header.type = fuzz_send ? 0x03 : 0x02;
      break;
    case BT_H4_ISO_PKT:
      header.type = fuzz_send ? 0x09 : 0x08;
      break;
    case BT_H4_EVT_PKT:
      header.type = 0x01;
      break;
    default:
      return;
  }

  fwrite(&header, sizeof(header), 1, f);
}

void save_pklg_internal(afl_state_t *afl, char *dir_in) {
  struct dirent **nl;
  s32             nl_cnt, subdirs = 1;
  u32             t = 0;
  char *          fn_in, *fn_out, *dir_out;
  FILE *          f_in, *f_out;
  struct stat     st;
  u32             message_cnt;
  message_t *     message;

  dir_out = alloc_printf("%s%s", dir_in, "_pklg");

  nl_cnt = scandir(dir_in, &nl, NULL, alphasort);

  for (int i = 0; i < nl_cnt; ++i) {
    message = afl_realloc(AFL_BUF_PARAM(out_scratch), sizeof(message_t));

    fn_in = alloc_printf("%s/%s", dir_in, nl[i]->d_name);
    fn_out = alloc_printf("%s/%s", dir_out, nl[i]->d_name);

    if (lstat(fn_in, &st) || access(fn_in, R_OK)) { continue; }

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn_in, "/README.txt")) {
      continue;
    }

    f_in = fopen(fn_in, "r");
    f_out = fopen(fn_out, "w");

    fread(&message_cnt, sizeof(u32), 1, f_in);

    for (int j = 0; j < message_cnt; ++j) {
      fread(message, sizeof(*message), 1, f_in);

      message = afl_realloc(AFL_BUF_PARAM(out_scratch),
                            message->size + sizeof(*message));

      fread(message->data, 1, message->size, f_in);

      if (message->type != FUZZ_SEND) { t += message->time; }

      if (message->type == FUZZ_RECV_TMOUT) { continue; }

      pklg_write_header(f_out, t / 1000000, t % 1000000, message->data[0],
                        message->type == FUZZ_SEND, message->size - 1);

      fwrite(&message->data[1], 1, message->size - 1, f_out);
    }

    fclose(f_in);
    fclose(f_out);
  }
}

void save_pklg(afl_state_t *afl) {
  char *dir = afl_realloc(AFL_BUF_PARAM(out), PATH_MAX);

  sprintf(dir, "%s/queue", afl->out_dir);
  save_pklg_internal(afl, dir);

  sprintf(dir, "%s/hangs", afl->out_dir);
  save_pklg_internal(afl, dir);

  sprintf(dir, "%s/crashes", afl->out_dir);
  save_pklg_internal(afl, dir);
}