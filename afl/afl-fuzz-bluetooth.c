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

void emit_message(afl_state_t *afl, queue_entry_t *q, u32 i) {
  int ack;
  message_t *message = q->messages[i];

  // qemu_hexdump(message->data, stdout, "Fuzz Send", message->size);

  controller_send(message->data, message->size);
  afl->message_emitted = 1;

  if (!buzzer->no_ack) {
    ack = controller_recv_ack(100);
    if (ack == -2){
       afl->messages_rcvd = -1;
    }
    else {
      afl->messages_rcvd += (ack & 0xFFFF);
    }
  }
}

void emit_cmd_status(afl_state_t *afl, queue_entry_t *q, u16 opcode,
                     u8 status) {
  queue_entry_append_event(q, BT_HCI_EVT_CMD_STATUS, bt_hci_evt_cmd_status,
                           sizeof(bt_hci_evt_cmd_status));
  evt_params->ncmd = 10;
  evt_params->opcode = opcode;
  evt_params->status = status;
  emit_message(afl, q, q->message_cnt - 1);
}

void emit_cmd_complete(afl_state_t *afl, queue_entry_t *q, u16 opcode,
                       void *payload, u32 size) {
  queue_entry_append_event(q, BT_HCI_EVT_CMD_COMPLETE, bt_hci_evt_cmd_complete,
                           sizeof(bt_hci_evt_cmd_complete) + size);
  evt_params->ncmd = 10;
  evt_params->opcode = opcode;
  memcpy(evt_params->params, payload, size);
  emit_message(afl, q, q->message_cnt - 1);
}

void emit_cmd_complete_success(afl_state_t *afl, queue_entry_t *q, u16 opcode) {
  u8 status = BT_HCI_ERR_SUCCESS;
  emit_cmd_complete(afl, q, opcode, &status, sizeof(status));
}

void emit_le_event(afl_state_t *afl, queue_entry_t *q, u8 opcode, void *payload,
                   u32 size) {
  queue_entry_append_le_event(q, opcode, u8, size);
  memcpy(evt_params, payload, size);
  emit_message(afl, q, q->message_cnt - 1);
}

void emit_le_adv_report(afl_state_t *afl, queue_entry_t *q) {
  const u8 adv_data[] = {
    0x02, 0x01, 0x06, 0x0b, 0x09, 0x42, 0x75, 0x7a,
    0x65, 0x72, 0x46, 0x75, 0x7a, 0x7a, 0x00
  };

  u8       rsp_data[255];
  bt_hci_evt_le_adv_report *rsp = (void *)rsp_data;
  rsp->num_reports = 1;
  rsp->event_type = 0;
  rsp->addr_type = 0;
  memcpy(rsp->addr, "remote", 6);
  rsp->data_len = sizeof(adv_data);
  memcpy(rsp->data, adv_data, sizeof(adv_data));
  emit_le_event(afl, q, BT_HCI_EVT_LE_ADV_REPORT, rsp,
                sizeof(*rsp) + sizeof(adv_data));
}

void emit_discon_complete(afl_state_t *afl, queue_entry_t *q, u16 handle) {
  queue_entry_append_event(q, BT_HCI_EVT_DISCONNECT_COMPLETE,
                           bt_hci_evt_disconnect_complete,
                           sizeof(bt_hci_evt_disconnect_complete));
  evt_params->status = BT_HCI_ERR_SUCCESS;
  evt_params->handle = handle;
  evt_params->reason = rand_below(afl, UINT8_MAX);
  emit_message(afl, q, q->message_cnt - 1);
  afl->bt_state.conns[handle].state = DISCONNECTED;
}

void emit_conn_request(afl_state_t *afl, queue_entry_t *q, u16 handle) {
  queue_entry_append_event(q, BT_HCI_EVT_CONN_REQUEST, bt_hci_evt_conn_request,
                           sizeof(bt_hci_evt_conn_request));
  evt_params->link_type = LINK_TYPE_ACL;
  memcpy(evt_params->bdaddr, bd_addr_remote, 6);
  rand_bytes(afl, evt_params->dev_class, sizeof(evt_params->dev_class));
  emit_message(afl, q, q->message_cnt - 1);
  afl->bt_state.conns[handle].state = SENT_CONN_REQ;
}

void emit_conn_complete(afl_state_t *afl, queue_entry_t *q, u16 handle,
                        u8 status) {
  if (handle == BREDR_HANDLE) {
    queue_entry_append_event(q, BT_HCI_EVT_CONN_COMPLETE,
                             bt_hci_evt_conn_complete,
                             sizeof(bt_hci_evt_conn_complete));
    memcpy(evt_params->bdaddr, bd_addr_remote, 6);
    evt_params->handle = handle;
    evt_params->status = status;
    evt_params->encr_mode = rand_below(afl, 3);
    evt_params->link_type = LINK_TYPE_ACL;
  } 
  else {
    queue_entry_append_le_event(q, BT_HCI_EVT_LE_CONN_COMPLETE,
                                bt_hci_evt_le_conn_complete,
                                sizeof(bt_hci_evt_le_conn_complete));
    rand_bytes(afl, evt_params, sizeof(*evt_params));
    memcpy(evt_params->peer_addr, bd_addr_remote, 6);
    evt_params->handle = handle;
    evt_params->status = status;
    evt_params->peer_addr_type = rand_below(afl, 3);
    evt_params->role = rand_below(afl, 2);
    evt_params->role = 1;
  }
  emit_message(afl, q, q->message_cnt - 1);
  afl->bt_state.conns[handle].state = CONNECTED;
}

void emit_num_completed_packets(afl_state_t *afl, queue_entry_t *q,
                                u16 handle) {
  queue_entry_append_event(q, BT_HCI_EVT_NUM_COMPLETED_PACKETS,
                           bt_hci_evt_num_completed_packets,
                           sizeof(bt_hci_evt_num_completed_packets));
  evt_params->num_handles = 1;
  evt_params->handle = handle;
  evt_params->count = 1;
  emit_message(afl, q, q->message_cnt - 1);
}

u8 is_link_change_event(message_t *message) {
  if (message->data[0] == BT_H4_EVT_PKT) {
    bt_hci_evt_hdr *evt = (void *)&message->data[1];
    if (evt->evt == BT_HCI_EVT_CONN_COMPLETE ||
        evt->evt == BT_HCI_EVT_DISCONNECT_COMPLETE ||
        evt->evt == BT_HCI_EVT_CONN_REQUEST) {
      return true;
    }
    if (evt->evt == BT_HCI_EVT_LE_META_EVENT) {
      if (evt->params[0] == BT_HCI_EVT_LE_CONN_COMPLETE) { return true; }
    }
  }
  return 0;
}

void emit_link_change_event(afl_state_t *afl, queue_entry_t *q, u16 handle) {
  bt_state_t *bt = &afl->bt_state;
  switch (bt->conns[handle].state) {
    case RCVD_CREATE_CONN:
      emit_conn_complete(afl, q, handle, BT_HCI_ERR_SUCCESS);
      break;

    case RCVD_ACCEPT_CONN:
      emit_conn_complete(afl, q, handle, BT_HCI_ERR_SUCCESS);
      break;

    case RCVD_REJECT_CONN:
      emit_conn_complete(afl, q, handle, rand_below(afl, UINT8_MAX) + 1);
      break;

    case RCVD_CONN_CANCEL:
      emit_conn_complete(afl, q, handle, BT_HCI_ERR_UNKNOWN_CONN_ID);
      break;

    case RCVD_DISCON:
      emit_discon_complete(afl, q, handle);
      break;

    case SENT_CONN_REQ:
    case CONNECTED:
      emit_discon_complete(afl, q, handle);
      break;

    case DISCONNECTED:
      if (handle == LE_HANDLE) {
        emit_conn_complete(afl, q, handle, BT_HCI_ERR_SUCCESS);
      } else {
        emit_conn_request(afl, q, handle);
      }
      break;

    default:
      FATAL("");
  }
}

void emit_event_from_format(afl_state_t *afl, queue_entry_t *q,
                            hci_evt_format_t *fmt) {
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

  queue_entry_append_event(q, opcode, u8, fmt->size);

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

  emit_message(afl, q, q->message_cnt - 1);
}

void emit_event(afl_state_t *afl, queue_entry_t *q, u8 opcode, void *payload,
                u32 size) {
  queue_entry_append_event(q, opcode, u8, size);
  memcpy(evt_params, payload, size);
  emit_message(afl, q, q->message_cnt - 1);
}

void emit_event_random(afl_state_t *afl, queue_entry_t *q) {
  u32               r;
  u32               evt_cnt = hci_iut_evt_cnt();
  u32               le_evt_cnt = hci_iut_le_evt_cnt();
  hci_evt_format_t *fmt;

select_event:
  if (!buzzer->disable_bredr && !buzzer->disable_le) {
    r = rand_below(afl, 2);
    if (r == 0) {
      r = rand_below(afl, evt_cnt);
      fmt = get_hci_iut_evt_by_index(r);
    } else {
      r = rand_below(afl, le_evt_cnt);
      fmt = get_hci_iut_le_evt_by_index(r);
    }

  } else if (!buzzer->disable_bredr) {
    r = rand_below(afl, evt_cnt);
    fmt = get_hci_iut_evt_by_index(r);

  } else {
    r = rand_below(afl, le_evt_cnt);
    fmt = get_hci_iut_le_evt_by_index(r);
  }

  emit_event_from_format(afl, q, fmt);
}

void emit_l2cap_sig(afl_state_t *afl, queue_entry_t *q, u16 handle, u16 cid,
                    u8 ident, u8 code, void *payload, u32 size) {
  queue_entry_append_l2cap(q, handle, cid, bt_l2cap_sig_hdr,
                           sizeof(bt_l2cap_hdr) + size);
  l2cap_params->code = code;
  l2cap_params->ident = ident;
  l2cap_params->len = size;
  memcpy(l2cap_params->data, payload, size);
  emit_message(afl, q, q->message_cnt - 1);
  emit_num_completed_packets(afl, q, handle);
}

void emit_l2cap_sig_random(afl_state_t *afl, queue_entry_t *q, u16 handle) {
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

  u32 payload_size = 8;
  u32 payload_max_size =
      buzzer->acl_mtu
          ? buzzer->acl_mtu - sizeof(bt_l2cap_hdr) - sizeof(bt_l2cap_sig_hdr)
          : 128;
  u8 *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_max_size);
  memset(payload, 0, payload_max_size);
  payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val,
                            false, !afl->fuzz_mode, NULL, 0, payload_max_size);

  if (handle == LE_HANDLE) {
    emit_l2cap_sig(afl, q, handle, BT_L2CAP_CID_SIG_LE, ++ident,
                   le_sigs[rand_below(afl, sizeof(le_sigs))], payload,
                   payload_size);
  } else {
    emit_l2cap_sig(afl, q, handle, BT_L2CAP_CID_SIG, ++ident,
                   sigs[rand_below(afl, sizeof(sigs))], payload, payload_size);
  }
}

void emit_smp(afl_state_t *afl, queue_entry_t *q, u16 handle, u16 cid, u8 code,
              void *payload, u32 size) {
  queue_entry_append_l2cap(q, handle, cid, bt_l2cap_smp_hdr,
                           sizeof(bt_l2cap_smp_hdr) + size);
  l2cap_params->code = code;
  memcpy(l2cap_params->data, payload, size);
  emit_message(afl, q, q->message_cnt - 1);
  emit_num_completed_packets(afl, q, handle);
}

void emit_smp_random(afl_state_t *afl, queue_entry_t *q, u16 handle) {
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

  u32 payload_size = 8;
  u32 payload_max_size =
      buzzer->acl_mtu
          ? buzzer->acl_mtu - sizeof(bt_l2cap_hdr) - sizeof(bt_l2cap_sig_hdr)
          : 128;
  u8 *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_max_size);

  memset(payload, 0, payload_max_size);
  payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val,
                            false, !afl->fuzz_mode, NULL, 0, payload_max_size);

  if (handle == LE_HANDLE) {
    emit_smp(afl, q, handle, BT_L2CAP_CID_SMP,
             smps[rand_below(afl, sizeof(smps))], payload, payload_size);

  } else {
    emit_smp(afl, q, handle, BT_L2CAP_CID_SMP_BREDR,
             bredr_smps[rand_below(afl, sizeof(bredr_smps))], payload,
             payload_size);
  }
}

void emit_att(afl_state_t *afl, queue_entry_t *q, u16 handle, u8 code,
              void *payload, u32 size) {
  queue_entry_append_l2cap(q, handle, BT_L2CAP_CID_ATT, bt_l2cap_att_hdr,
                           sizeof(bt_l2cap_att_hdr) + size);
  l2cap_params->code = code;
  memcpy(l2cap_params->data, payload, size);
  emit_message(afl, q, q->message_cnt - 1);
  emit_num_completed_packets(afl, q, handle);
}

void emit_att_random(afl_state_t *afl, queue_entry_t *q, u16 handle) {
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

  u32 payload_size = 8;
  u32 payload_max_size =
      buzzer->acl_mtu
          ? buzzer->acl_mtu - sizeof(bt_l2cap_hdr) - sizeof(bt_l2cap_sig_hdr)
          : 128;
  u8 *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_max_size);
  memset(payload, 0, payload_max_size);
  payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val,
                            false, !afl->fuzz_mode, NULL, 0, payload_max_size);

  emit_att(afl, q, LE_HANDLE, atts[rand_below(afl, sizeof(atts))], payload,
           payload_size);
}

void emit_message_random(afl_state_t *afl, queue_entry_t *q) {
  enum {
    FUZZ_LINK_LE = 0,  // prob0
    FUZZ_LINK_BREDR,   // prob1
    FUZZ_EVENT,        // prob2 * 0.2
    FUZZ_L2CAP,        // prob2 * 0.4
    FUZZ_SMP,          //
    FUZZ_ATT           // prob2 * 0.2
  };

  u8     action, r;
  u16    handle;
  bt_state_t *bt = &afl->bt_state;
  double      prob, prob0 = 0, prob1 = 0, prob2 = 0;

  if (!buzzer->disable_le) {
    prob0 = hci_conn_change_state_prob(bt->le_conn);
  }

  if (!buzzer->disable_bredr) {
    prob1 = prob0 + hci_conn_change_state_prob(bt->bredr_conn);
  }

  prob = rand_next_percent(afl);

  if (prob < prob0) {
    emit_link_change_event(afl, q, LE_HANDLE);
    return;
  }
  else if (prob < prob1) {
    emit_link_change_event(afl, q, BREDR_HANDLE);
    return;
  }

  handle = bt_state_select_handle(afl);

  if (handle == INVALID_HANDLE) {
    emit_event_random(afl, q);
    return;
  }

  r = rand_below(afl, 9);
  
  if (r < 3) {
    emit_event_random(afl, q);
  }
  else if (r < 5) {
    emit_l2cap_sig_random(afl, q, handle);
  }
  else if (r < 7) {
    emit_smp_random(afl, q, handle);
  }
  else if (r < 9) {
    emit_att_random(afl, q, handle);
  }

  // prob2 = 1 - prob0 - prob1;

  // double probs[] = {prob0, prob1, prob2 * 0.3, prob2 * 0.4, 0, prob2 * 0.3};
  // action = prob_select(afl, probs, sizeof(probs) / sizeof(double));

  // switch (action) {
  //   case FUZZ_LINK_LE:
  //     emit_link_change_event(afl, q, LE_HANDLE);
  //     return;

  //   case FUZZ_LINK_BREDR:
  //     emit_link_change_event(afl, q, BREDR_HANDLE);
  //     return;

  //   case FUZZ_EVENT:
  //     emit_event_random(afl, q);
  //     return;

  //   case FUZZ_L2CAP:
  //     emit_l2cap_sig_random(afl, q);
  //     return;

  //   case FUZZ_SMP:
  //     emit_smp_random(afl, q);
  //     return;

  //   case FUZZ_ATT:
  //     emit_att_random(afl, q);
  //     return;

  //   default:
  //     FATAL("");
  // }
}

void queue_entry_load(queue_entry_t *q) {
  message_t *message;
  FILE      *f = fopen((char *)q->fname, "r");

  ck_fread(f, &q->message_cnt, sizeof(u32), q->fname);

  q->messages =
      afl_realloc((void **)&q->messages, q->message_cnt * sizeof(message_t *));

  if (unlikely(!f)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

  for (int i = 0; i < q->message_cnt; ++i) {
    message = afl_realloc((void **)&q->messages[i], sizeof(message_t));
    ck_fread(f, message, sizeof(message_t), q->fname);
    message = afl_realloc((void **)&q->messages[i],
                          message->size + sizeof(message_t));
    ck_fread(f, message->data, message->size, q->fname);
  }

  if (q->message_cnt > q->max_message_cnt) {
    q->max_message_cnt = q->message_cnt;
  }

  q->loaded = 1;

  fclose(f);
}

u32 queue_entry_save(queue_entry_t *q, char *fn) {
  u32        len = 0, message_cnt;
  message_t *message;
  FILE      *f = fopen(fn, "w");

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

void queue_entry_free_messages(queue_entry_t *q) {
  for (int i = 0; i < q->max_message_cnt; ++i) {
    afl_free(q->messages[i]);
    q->messages[i] = NULL;
  }
  afl_free(q->messages);
  q->messages = NULL;
}

void *queue_entry_alloc_message(queue_entry_t *q, u32 size) {
  if (++(q->message_cnt) > q->max_message_cnt) {
    ++(q->max_message_cnt);
    afl_realloc((void **)&q->messages, q->message_cnt * sizeof(message_t *));
  }

  afl_realloc((void **)&q->messages[q->message_cnt - 1],
              size + sizeof(message_t));
  q->messages[q->message_cnt - 1]->type = FUZZ_SEND;
  q->messages[q->message_cnt - 1]->size = size;
  return q->messages[q->message_cnt - 1]->data;
}

void queue_entry_append_message(queue_entry_t *q, uint8_t *buf, u32 len) {
  message_t *message;
  message = queue_entry_alloc_message(q, 0);
  message = &message[-1];
  memcpy(message->data, buf, len);
}

void queue_entry_append_message_recv(queue_entry_t *q, uint8_t *buf, u32 len) {
  message_t *message;
  message = queue_entry_alloc_message(q, len);
  message = &message[-1];
  message->type = FUZZ_RECV_OK;
  memcpy(message->data, buf, len);
}

void queue_entry_append_message_tmout(queue_entry_t *q) {
  message_t *message;
  message = queue_entry_alloc_message(q, 0);
  message = &message[-1];
  message->type = FUZZ_RECV_TMOUT;
}

void queue_entry_pop_message(queue_entry_t *q) {
  q->message_cnt--;
}

void queue_entry_clear_messages(queue_entry_t *q) {
  q->message_cnt = 0;
}

message_t *queue_entry_message_tail(queue_entry_t *q) {
  return q->messages[q->message_cnt - 1];
}

u32 queue_entry_exec_us(queue_entry_t *q) {
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

void trace_message_bits(afl_state_t *afl, queue_entry_t *q) {
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

void dump_messages(queue_entry_t *q) {
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

u8 handle_acl(afl_state_t *afl, queue_entry_t *q, bt_hci_acl_hdr *acl) {
  u16 handle = acl->handle & 0xFFF;
  u32 payload_size = 8;
  u32 payload_max_size =
      buzzer->acl_mtu
          ? buzzer->acl_mtu - sizeof(bt_l2cap_hdr) - sizeof(bt_l2cap_sig_hdr)
          : 128;
  u8           *payload = afl_realloc(AFL_BUF_PARAM(out_scratch), payload_size);
  bt_l2cap_hdr *l2cap = (void *)acl->data;
  bt_state_t   *bt = &afl->bt_state;

  bt_state_update_from_acl(bt, acl);

  if (l2cap->cid == BT_L2CAP_CID_SIG_LE || l2cap->cid == BT_L2CAP_CID_SIG) {
    bt_l2cap_sig_hdr *sig = (void *)l2cap->data;

    if (unlikely(l2cap->len != sig->len + sizeof(*sig))) return 2;

    memset(payload, 0, payload_size);
    payload_size = afl_mutate(afl, payload, payload_size, afl->stage_cur_val, 0,
                              !afl->fuzz_mode, NULL, 0, payload_max_size);

    switch (sig->code) {
      case BT_L2CAP_PDU_CONN_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_CONN_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_CONFIG_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_CONFIG_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_DISCONN_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_DISCONN_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_ECHO_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_ECHO_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_INFO_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_INFO_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_CREATE_CHAN_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_CREATE_CHAN_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_MOVE_CHAN_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_MOVE_CHAN_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_MOVE_CHAN_CFM:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_MOVE_CHAN_CFM_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_CONN_PARAM_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_CONN_PARAM_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_LE_CONN_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_LE_CONN_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_ECRED_CONN_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_ECRED_CONN_RSP, payload, payload_size);
        break;

      case BT_L2CAP_PDU_ECRED_RECONF_REQ:
        emit_l2cap_sig(afl, q, handle, l2cap->cid, sig->ident,
                       BT_L2CAP_PDU_ECRED_RECONF_RSP, payload, payload_size);
        break;
    }

  } else if (l2cap->cid == BT_L2CAP_CID_ATT) {
    bt_l2cap_att_hdr *att = (void *)l2cap->data;
    switch (att->code) {
      case BT_L2CAP_ATT_EXCHANGE_MTU_REQ:
        emit_att(afl, q, handle, BT_L2CAP_ATT_EXCHANGE_MTU_RSP, payload,
                 payload_size);
        break;

      case BT_L2CAP_ATT_READ_TYPE_REQ:
        emit_att(afl, q, handle, BT_L2CAP_ATT_READ_TYPE_RSP, payload,
                 payload_size);
        break;

      case BT_L2CAP_ATT_READ_REQ:
        emit_att(afl, q, handle, BT_L2CAP_ATT_READ_RSP, payload, payload_size);
        break;

      case BT_L2CAP_ATT_READ_GROUP_TYPE_REQ:
        emit_att(afl, q, handle, BT_L2CAP_ATT_READ_GROUP_TYPE_REQ, payload,
                 payload_size);
        break;

      case BT_L2CAP_ATT_HANDLE_VALUE_IND:
        emit_att(afl, q, handle, BT_L2CAP_ATT_HANDLE_VALUE_CONF, payload,
                 payload_size);
        break;
    }
  }
  return 0;
}

static void handle_read_local_version(afl_state_t *afl, queue_entry_t *q,
                                      bt_hci_cmd_hdr *cmd) {
  bt_hci_rsp_read_local_version rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rsp.hci_ver = 0x0C;
  rsp.hci_rev = 0x3484;
  rsp.lmp_ver = 0x0C;
  rsp.manufacturer = 0x02;
  rsp.lmp_subver = 0x3484;
  emit_cmd_complete(afl, q, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_local_name(afl_state_t *afl, queue_entry_t *q,
                                   bt_hci_cmd_hdr *cmd) {
  bt_hci_rsp_read_local_name rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  strcpy(rsp.name, "buzzer");
  emit_cmd_complete(afl, q, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_local_commands(afl_state_t *afl, queue_entry_t *q,
                                       bt_hci_cmd_hdr *cmd) {
  bt_hci_rsp_read_local_commands rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  memset(&rsp.commands[0], 0xFF, 64);
  emit_cmd_complete(afl, q, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_bd_addr(afl_state_t *afl, queue_entry_t *q,
                                bt_hci_cmd_hdr *cmd) {
  bt_hci_rsp_read_bd_addr rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  memcpy(rsp.bdaddr, "local", 6);
  emit_cmd_complete(afl, q, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_buffer_size(afl_state_t *afl, queue_entry_t *q,
                                    bt_hci_cmd_hdr *cmd) {
  bt_hci_rsp_read_buffer_size rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rsp.acl_max_pkt = BZ_ACL_MAX_PKT;
  rsp.acl_mtu = BZ_ACL_MTU;
  rsp.sco_max_pkt = BZ_SCO_MAX_PKT;
  rsp.sco_mtu = BZ_SCO_MTU;
  emit_cmd_complete(afl, q, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_local_features(afl_state_t *afl, queue_entry_t *q,
                                       bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_read_local_features rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  memset(rsp.features, 0xFF, sizeof(rsp.features));
  // The 37th bit (BR/EDR not supported) should be 0
  // The 4th byte should be 0x11011111
  rsp.features[4] = 0xDF;
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
}

static void handle_host_buffer_size(afl_state_t *afl, queue_entry_t *q,
                                    bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_host_buffer_size *cmd = (void *)cmd_hdr->params;
  buzzer->acl_mtu = cmd->acl_mtu;
  buzzer->acl_max_pkt = cmd->acl_max_pkt;
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
}

static void handle_set_event_mask(afl_state_t *afl, queue_entry_t *q,
                                  bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_set_event_mask *cmd = (void *)cmd_hdr->params;
  for (int i = 0; i < 8; ++i) {
    u8 mask = cmd->mask[i];
    for (int j = 0; j < 8; ++j) {
      if (!((mask >> j) & 0x1)) { hci_event_mask[i * 8 + j] = 0; }
    }
  }
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
  update_event_mask_map();
}

static void handle_set_event_mask_page2(afl_state_t *afl, queue_entry_t *q,
                                        bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_set_event_mask_page2 *cmd = (void *)cmd_hdr->params;
  for (int i = 0; i < 8; ++i) {
    u8 mask = cmd->mask[i];
    for (int j = 0; j < 8; ++j) {
      if (!((mask >> j) & 0x1)) { hci_event_mask_page2[i * 8 + j] = 0; }
    }
  }
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
  update_event_mask_page2_map();
}

static void handle_le_read_local_features(afl_state_t *afl, queue_entry_t *q,
                                          bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_read_local_features rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  memset(rsp.features, 0xFF, sizeof(rsp.features));
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
  update_le_event_mask_map();
}

static void handle_le_read_buffer_size(afl_state_t *afl, queue_entry_t *q,
                                       bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_read_buffer_size rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rsp.le_max_pkt = 10;
  rsp.le_mtu = 0xFFFF;
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
}

static void handle_le_read_buffer_size_v2(afl_state_t *afl, queue_entry_t *q,
                                          bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_read_buffer_size_v2 rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rsp.acl_mtu = 0xFFFF;
  rsp.acl_max_pkt = 10;
  rsp.iso_mtu = 0;
  rsp.iso_max_pkt = 0;
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
}

static void handle_write_le_host_supported(afl_state_t *afl, queue_entry_t *q,
                                           bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_write_le_host_supported *cmd = (void *)cmd_hdr->params;
}

static void handle_le_read_supported_states(afl_state_t *afl, queue_entry_t *q,
                                            bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_read_supported_states rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  memset(rsp.states, 0xFF, sizeof(rsp.states));
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(&rsp));
}

static void handle_le_read_max_data_length(afl_state_t *afl, queue_entry_t *q,
                                           bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_read_max_data_length rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rsp.max_tx_len = 0xFFFF;
  rsp.max_tx_time = 0xFFFF;
  rsp.max_rx_len = 0xFFFF;
  rsp.max_rx_time = 0xFFFF;
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
}

static void handle_le_read_resolve_list_size(afl_state_t *afl, queue_entry_t *q,
                                             bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_read_resolv_list_size rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rsp.size = 0;
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
}

static void handle_le_set_event_mask(afl_state_t *afl, queue_entry_t *q,
                                     bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_le_set_event_mask *cmd = (void *)cmd_hdr->params;
  for (int i = 0; i < 8; ++i) {
    u8 mask = cmd->mask[i];
    for (int j = 0; j < 8; ++j) {
      if (!((mask >> j) & 0x1)) { hci_le_event_mask[i * 8 + j] = 0; }
    }
  }
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
  update_le_event_mask_map();
}

static void handle_le_set_random_address(afl_state_t *afl, queue_entry_t *q,
                                         bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_le_set_random_address *cmd = (void *)cmd_hdr->params;
  cmd->addr;
}

static void handle_le_set_scan_parameters(afl_state_t *afl, queue_entry_t *q,
                                          bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_le_set_scan_parameters *cmd = (void *)cmd_hdr->params;
  afl->bt_state.filter_policy = cmd->filter_policy;
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
}

static void handle_le_set_scan_enable(afl_state_t *afl, queue_entry_t *q,
                                      bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_le_set_scan_enable *cmd = (void *)cmd_hdr->params;
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
  if (cmd->enable) {
    const u8 adv_data[] = {0x02, 0x01, 0x06, 0x0b, 0x09, 0x42, 0x75, 0x7a,
                           0x65, 0x72, 0x46, 0x75, 0x7a, 0x7a, 0x00};
    u8       rsp_data[255];
    bt_hci_evt_le_adv_report *rsp = (void *)rsp_data;
    rsp->num_reports = 1;
    rsp->event_type = 0;
    rsp->addr_type = 0;
    memcpy(rsp->addr, "remote", 6);
    rsp->data_len = sizeof(adv_data);
    memcpy(rsp->data, adv_data, sizeof(adv_data));
    emit_le_event(afl, q, BT_HCI_EVT_LE_ADV_REPORT, rsp,
                  sizeof(*rsp) + sizeof(adv_data));
  }
}

static void handle_le_set_adv_enable(afl_state_t *afl, queue_entry_t *q,
                                     bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_le_set_adv_enable *cmd = (void *)cmd_hdr->params;
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
  // if (cmd->enable) {
  //   emit_conn_complete(afl, q, LE_HANDLE, BT_HCI_ERR_SUCCESS);
  // }
}

static void handle_le_rand(afl_state_t *afl, queue_entry_t *q, bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_rsp_le_rand rsp;
  rsp.status = BT_HCI_ERR_SUCCESS;
  rand_bytes(afl, &rsp.number, sizeof(rsp.number));
  emit_cmd_complete(afl, q, cmd_hdr->opcode, &rsp, sizeof(rsp));
}

static void handle_le_read_remote_features(afl_state_t *afl, queue_entry_t *q, bt_hci_cmd_hdr *cmd_hdr) {
  bt_hci_cmd_read_remote_features *cmd = (void *)cmd_hdr->params;
  emit_cmd_complete_success(afl, q, cmd_hdr->opcode);
  queue_entry_append_event(q, BT_HCI_EVT_REMOTE_FEATURES_COMPLETE, 
                              bt_hci_evt_remote_features_complete,
                              sizeof(bt_hci_evt_remote_features_complete));
  evt_params->status = BT_HCI_ERR_SUCCESS;
  evt_params->handle = cmd->handle;
  rand_bytes(afl, evt_params->features, sizeof(evt_params->features));
  emit_message(afl, q, q->message_cnt - 1);
}

static u8 handle_command_prio(afl_state_t *afl, queue_entry_t *q,
                              bt_hci_cmd_hdr *cmd) {
  switch (cmd->opcode) {
    case BT_HCI_CMD_LE_RAND:
      handle_le_rand(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_REMOTE_FEATURES:
      handle_le_read_remote_features(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_READ_LOCAL_VERSION:
      handle_read_local_version(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_READ_LOCAL_NAME:
      handle_read_local_name(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_READ_LOCAL_COMMANDS:
      handle_read_local_commands(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_READ_BD_ADDR:
      handle_read_bd_addr(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_READ_BUFFER_SIZE:
      handle_read_buffer_size(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_READ_LOCAL_FEATURES:
      handle_read_local_features(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_HOST_BUFFER_SIZE:
      handle_host_buffer_size(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_SET_EVENT_MASK:
      handle_set_event_mask(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_SET_EVENT_MASK_PAGE2:
      handle_set_event_mask_page2(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_SET_EVENT_MASK:
      handle_le_set_event_mask(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_LOCAL_FEATURES:
      handle_le_read_local_features(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_BUFFER_SIZE:
      handle_le_read_buffer_size(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_BUFFER_SIZE_V2:
      handle_le_read_buffer_size_v2(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_SUPPORTED_STATES:
      handle_le_read_supported_states(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH:
      handle_le_read_max_data_length(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE:
      handle_le_read_resolve_list_size(afl, q, cmd);
      return 1;

    // case BT_HCI_CMD_LE_READ_LOCAL_PK256:
    //   handle_le_read_local_pk256(this, cmd);
    //   break;

    // case BT_HCI_CMD_LE_SET_RANDOM_ADDRESS:
    //   handle_le_set_random_address(this, cmd);
    //   break;

    case BT_HCI_CMD_LE_SET_SCAN_PARAMETERS:
      handle_le_set_scan_parameters(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_SET_SCAN_ENABLE:
      handle_le_set_scan_enable(afl, q, cmd);
      return 1;

    case BT_HCI_CMD_LE_SET_ADV_ENABLE:
      handle_le_set_adv_enable(afl, q, cmd);
      return 1;
  }
  return 0;
}

u8 handle_command(afl_state_t *afl, queue_entry_t *q, bt_hci_cmd_hdr *cmd) {
  u8               *rsp;
  hci_cmd_format_t *cmd_fmt;
  bt_state_t       *bt = &afl->bt_state;
  u8               *bd_addrs[] = {bd_addr_local, bd_addr_remote};

  if (cmd->opcode == BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS) { return 1;}

  if (handle_command_prio(afl, q, cmd)) { return 0; }

  cmd_fmt = get_hci_cmd(cmd->opcode);

  if (!cmd_fmt) { FATAL("Command 0x%04x not found", cmd->opcode); }

  if (cmd_fmt->opcode == BT_HCI_CMD_RESET) {
    afl->hci_reset_handled = 1;
  }

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

    emit_cmd_complete(afl, q, cmd->opcode, rsp, cmd_fmt->rsp_size);

  } else {
    // We should send a command_status_event
    emit_cmd_status(afl, q, cmd->opcode, BT_HCI_ERR_SUCCESS);
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
      emit_event(afl, q, BT_HCI_EVT_LE_META_EVENT, rsp, rsp_fmt->size);
    } else {
      emit_event(afl, q, rsp_fmt->opcode, rsp, rsp_fmt->size);
    }
  }

  return 0;
}

int recv_messages(afl_state_t *afl, queue_entry_t *q, u8 append) {
  int n = 0, tmout_ms, pktlen;
  if (!buzzer->no_ack) {
    n = afl->messages_rcvd;
    for (int i = 0; i < n; ++i) {
      pktlen = controller_recv(buzzer->mbuf, 10000000);
      if (append) {
        queue_entry_append_message_recv(q, buzzer->mbuf, pktlen);
      }
    }
  }
  else {
    tmout_ms = BZ_TMOUT_MS;
    while (1) {
      pktlen = controller_recv(buzzer->mbuf, tmout_ms);
      if (pktlen == -2) { break; }
      if (append) {
        queue_entry_append_message_recv(q, buzzer->mbuf, pktlen);
      }
      tmout_ms = 0;
      n++;
    }
  }
  return n;
}

u8 recv_message(afl_state_t *afl, queue_entry_t *q, u8 handle) {
  int             pktlen = 0;
  int             tmout_ms = BZ_TMOUT_MS;
  u8              retry = 0, skip = 0;
  bt_hci_cmd_hdr *cmd_hdr;
  bt_hci_acl_hdr *acl_hdr;
  bt_hci_sco_hdr *sco_hdr;
  bt_hci_iso_hdr *iso_hdr;

  while (1) {
    pktlen = controller_recv(buzzer->mbuf + buzzer->mbuf_len, tmout_ms);
  }

retry_stage:

  pktlen = controller_recv(buzzer->mbuf + buzzer->mbuf_len, tmout_ms);

  if (pktlen == -2) {
    return FSRV_RUN_TMOUT;
  } else if (unlikely(pktlen < 0)) {
    FATAL("Recv message failed");
  }

  buzzer->mbuf_len += pktlen;

#define RETRY_RECV                    \
  do {                                \
    if (retry) return FSRV_RUN_TMOUT; \
    retry = 1;                        \
    tmout_ms = 0;                     \
    goto retry_stage;                 \
  } while (0);

process_stage:
  if (unlikely(buzzer->mbuf_len < 1)) { RETRY_RECV; }

  switch (buzzer->mbuf[0]) {
    case BT_H4_CMD_PKT:
      if (buzzer->mbuf_len < 1 + sizeof(*cmd_hdr)) { RETRY_RECV; }
      cmd_hdr = (void *)(buzzer->mbuf + 1);
      pktlen = 1 + sizeof(*cmd_hdr) + cmd_hdr->plen;
      if (cmd_hdr->opcode == BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS) {
        skip = 1;
      }
      break;

    case BT_H4_ACL_PKT:
      if (buzzer->mbuf_len < 1 + sizeof(*acl_hdr)) { RETRY_RECV; }
      acl_hdr = (void *)(buzzer->mbuf + 1);
      pktlen = 1 + sizeof(*acl_hdr) + acl_hdr->dlen;
      break;

    case BT_H4_SCO_PKT:
      if (buzzer->mbuf_len < 1 + sizeof(*sco_hdr)) { RETRY_RECV; }
      sco_hdr = (void *)(buzzer->mbuf + 1);
      pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;
      break;

    case BT_H4_ISO_PKT:
      if (buzzer->mbuf_len < 1 + sizeof(*iso_hdr)) { RETRY_RECV; }
      iso_hdr = (void *)(buzzer->mbuf + 1);
      pktlen = 1 + sizeof(*iso_hdr) + iso_hdr->dlen;
      break;

    default:
      return FSRV_RUN_CRASH;
  }

  if (buzzer->mbuf_len < pktlen) return;

  queue_entry_append_message_recv(q, buzzer->mbuf, pktlen);
  qemu_hexdump(buzzer->mbuf, stdout, "recv", pktlen);
  if (handle && !skip) { handle_message(afl, q, buzzer->mbuf, pktlen); }

  if (skip) {
    memmove(buzzer->mbuf, buzzer->mbuf + pktlen, buzzer->mbuf_len - pktlen);
    buzzer->mbuf_len -= pktlen;
    skip = 0;
    goto retry_stage;
  }

  if (afl->stats_avg_exec > 60 && afl->passed_iut_init) {
    qemu_hexdump(buzzer->mbuf, stdout, "Fuzz Recv", pktlen);
    // static int cnt = 0;
    // ++cnt;
    // if (cnt > 10) {
    //   cnt = 0;
    //   return FSRV_RUN_CRASH;
    // }
  }

  if (buzzer->mbuf_len > pktlen) {
    memmove(buzzer->mbuf, buzzer->mbuf + pktlen, buzzer->mbuf_len - pktlen);
    buzzer->mbuf_len -= pktlen;
    goto process_stage;
  }

  buzzer->mbuf_len = 0;

#undef RETRY_RECV

  return FSRV_RUN_OK;
}

u8 __attribute__((noinline))
handle_message(afl_state_t *afl, queue_entry_t *q, u8 *buf, u32 len) {
  u8 *end;
  u32 size, messages = 0;
  u8  use_new = 1, new_appended = 0;

  if (!len) { return; }

  if (*buf == BT_H4_CMD_PKT) {
    bt_hci_cmd_hdr *cmd = (bt_hci_cmd_hdr *)(&buf[1]);
    return handle_command(afl, q, cmd);
  } else if (*buf == BT_H4_ACL_PKT) {
    bt_hci_acl_hdr *acl = (bt_hci_acl_hdr *)(&buf[1]);
    return handle_acl(afl, q, acl);
  }
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
  memcpy(dest, src, sizeof(*dest));
  dest->le_conn = &dest->conns[LE_HANDLE];
  dest->bredr_conn = &dest->conns[BREDR_HANDLE];
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
      bt_hci_evt_conn_complete *cc = (void *)evt->params;
      if (cc->status == BT_HCI_ERR_SUCCESS) {
        hci_conn_set_state(bt->bredr_conn, CONNECTED);
      } else {
        hci_conn_set_state(bt->bredr_conn, DISCONNECTED);
      }
      break;

    case BT_HCI_EVT_DISCONNECT_COMPLETE:
      bt_hci_evt_disconnect_complete *disc = (void *)evt->params;
      hci_conn_set_state(&bt->conns[disc->handle], DISCONNECTED);
      break;

    case BT_HCI_EVT_LE_META_EVENT:
      if (evt->params[0] == BT_HCI_EVT_LE_CONN_COMPLETE) {
        if (evt->params[0] == BT_HCI_ERR_SUCCESS) {
          hci_conn_set_state(bt->le_conn, CONNECTED);
        } else {
          hci_conn_set_state(bt->le_conn, DISCONNECTED);
        }
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
      bt_hci_cmd_disconnect *disc = (void *)(cmd->params);
      hci_conn_set_state(&bt->conns[disc->handle], RCVD_DISCON);
      break;

    default:
      break;
  }
}

void bt_state_update(bt_state_t *bt, message_t *message) {
  if (message->type == FUZZ_RECV_OK) {
    if (message->data[0] == BT_H4_CMD_PKT) {
      bt_state_update_from_cmd(bt, (bt_hci_cmd_hdr *)&message->data[1]);
    } else if (message->data[0] == BT_H4_ACL_PKT) {
      bt_state_update_from_acl(bt, (bt_hci_acl_hdr *)&message->data[1]);
    }
  } else if (message->type == FUZZ_SEND) {
    if (message->data[0] == BT_H4_EVT_PKT) {
      bt_state_update_from_evt(bt, (bt_hci_evt_hdr *)&message->data[1]);
    } else if (message->data[0] == BT_H4_ACL_PKT) {
      bt_state_update_from_acl(bt, (bt_hci_acl_hdr *)&message->data[1]);
    }
  }
}

u16 bt_state_select_handle(afl_state_t *afl) {
  bt_state_t *bt = &afl->bt_state;
  if (bt->le_conn->state == CONNECTED && bt->bredr_conn->state == CONNECTED) {
    return rand_below(afl, 2);

  } else if (bt->le_conn->state == CONNECTED) {
    return LE_HANDLE;

  } else if (bt->bredr_conn->state == CONNECTED) {
    return BREDR_HANDLE;

  } else {
    return INVALID_HANDLE;
  }
}

double hci_conn_change_state_prob(hci_conn_t *conn) {
  if (conn->handle == LE_HANDLE && buzzer->disable_le) {
    return 0;
  }

  if (conn->handle == BREDR_HANDLE && buzzer->disable_bredr) {
    return 0;
  }

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

void bt_state_simulate(bt_state_t *bt, queue_entry_t *q) {
  message_t *message;
  for (int i = 0; i < q->message_cnt; ++i) {
    message = q->messages[i];
    bt_state_update(bt, message);
  }
}

void enumerate_event(afl_state_t *afl, struct queue_entry *q, u8 opcode,
                     u32 size) {
  memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother, afl->fsrv.map_size);

  queue_entry_clear_messages(q);

  queue_entry_append_event(q, opcode, u8, size);

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  afl->messages_rcvd = 0;

  emit_message(afl, q, 0);

  recv_messages(afl, q, 0);

  // controller_recv_drain(buzzer->mbuf);

  afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

  ACTF("0x%02x", opcode);

  classify_counts(&afl->fsrv);

  if (2 == has_new_bits(afl, afl->virgin_bits)) {
    OKF("0x%02x", opcode);
    add_hci_iut_evt(opcode);
  }

  clear_exec_fail_sig(afl->fsrv.trace_bits);
}

void enumerate_le_event(afl_state_t *afl, struct queue_entry *q, u8 opcode,
                        u32 size) {
  memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother, afl->fsrv.map_size);

  queue_entry_clear_messages(q);

  queue_entry_append_le_event(q, opcode, u8, size);

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  afl->messages_rcvd = 0;

  emit_message(afl, q, 0);

  recv_messages(afl, q, 0);

  // controller_recv(buzzer->mbuf, BZ_TMOUT_MS);

  // controller_recv_drain(buzzer->mbuf);

  afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

  ACTF("0x%02x", opcode);

  classify_counts(&afl->fsrv);

  if (2 == has_new_bits(afl, afl->virgin_bits)) {
    OKF("0x%02x", opcode);
    add_hci_iut_le_evt(opcode);
  }

  clear_exec_fail_sig(afl->fsrv.trace_bits);
}

void dry_run_event(afl_state_t *afl, struct queue_entry *q, u8 opcode,
                   u32 size) {
  queue_entry_clear_messages(q);

  memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother, afl->fsrv.map_size);

  queue_entry_append_event(q, opcode, u8, size);

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  afl->messages_rcvd = 0;

  emit_message(afl, q, 0);

  recv_messages(afl, q, 0);

  // controller_recv(buzzer->mbuf, BZ_TMOUT_MS);

  // controller_recv_drain(buzzer->mbuf);

  afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

  classify_counts(&afl->fsrv);

  has_new_bits(afl, afl->virgin_bits);
}

void dry_run_le_event(afl_state_t *afl, struct queue_entry *q, u8 opcode,
                      u32 size) {
  queue_entry_clear_messages(q);

  memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother, afl->fsrv.map_size);

  queue_entry_append_le_event(q, opcode, u8, size);

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  afl->messages_rcvd = 0;

  emit_message(afl, q, 0);

  recv_messages(afl, q, 0);

  // controller_recv(buzzer->mbuf, BZ_TMOUT_MS);

  afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

  controller_recv_drain(buzzer->mbuf);

  classify_counts(&afl->fsrv);

  has_new_bits(afl, afl->virgin_bits);
}

// Given a message sequence, execute that sequence,
// create a forkserver spinning on the state after the sequence
u8 perform_dry_run(afl_state_t *afl, queue_entry_t *q) {
  message_t  *message;
  bt_state_t *bt = &afl->bt_state;
  int         tmout_ms, stat, n = 0, len = 0;

  afl->fsrv.trace_bits = buzzer->shmem_trace = buzzer->shmem_trace_mother;
  memcpy(afl->fsrv.trace_bits, buzzer->shmem_trace_root, afl->fsrv.map_size);

  bt_state_reset(bt);

  q->subseq_tmouts = 0;

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  for (int i = 0; i < q->message_cnt; ++i) {
    message = q->messages[i];
    if (message->type == FUZZ_SEND) {
      // qemu_hexdump(message->data, stdout, "fuzz send",message->size );
      // controller_send(message->data, message->size);

      afl->messages_rcvd = 0;

      emit_message(afl, q, i);

      recv_messages(afl, q, 0);

      // stat = controller_recv(buzzer->mbuf, BZ_TMOUT_MS);

      // if (unlikely(stat == -1)) {
      //   FATAL("Controller recv failed");
      // } else if (stat == -2) {
      //   q->subseq_tmouts++;
      // } else {
      //   q->subseq_tmouts = 0;
      //   // qemu_hexdump(buzzer->mbuf, stdout, "fuzz recv", stat);
      // }
    }
    bt_state_update(bt, message);
  }

  controller_recv_drain(buzzer->mbuf);

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
      header.type = (fuzz_send ? 0x03 : 0x02);
      break;
    case BT_H4_ISO_PKT:
      header.type = (fuzz_send ? 0x09 : 0x08);
      break;
    case BT_H4_EVT_PKT:
      header.type = 0x01;
      break;
    default:
      return;
  }

  fwrite(&header, sizeof(header), 1, f);
}

static void save_pklg_internal(afl_state_t *afl, char *dir_in) {
  struct dirent **nl;
  s32             nl_cnt, subdirs = 1;
  u32             t = 0;
  char           *fn_in, *fn_out, *dir_out;
  FILE           *f_in, *f_out;
  struct stat     st;
  u32             message_cnt;
  message_t      *message;

  dir_out = alloc_printf("%s%s", dir_in, "_pklg");

  nl_cnt = scandir(dir_in, &nl, NULL, alphasort);

  for (int i = 0; i < nl_cnt; ++i) {
    message = afl_realloc(AFL_BUF_PARAM(out_scratch), sizeof(message_t));

    fn_in = alloc_printf("%s/%s", dir_in, nl[i]->d_name);
    fn_out = alloc_printf("%s/%s", dir_out, nl[i]->d_name);

    if (lstat(fn_in, &st) || access(fn_in, R_OK)) { continue; }

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn_in, "/README.txt") ||
        strstr(fn_in, "_message")) {
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