#ifndef _AFL_FUZZ_BLUETOOTH_H
#define _AFL_FUZZ_BLUETOOTH_H

#include "afl/types.h"

#define LE_HANDLE 0
#define BREDR_HANDLE 1
#define MAX_CIDS 20

enum {
  DISCONNECTED = 0,
  RCVD_CREATE_CONN,
  RCVD_ACCEPT_CONN,
  RCVD_REJECT_CONN,
  RCVD_CONN_CANCEL,
  RCVD_DISCON,
  SENT_CONN_REQ,
  CONNECTED,
};

typedef struct hci_conn {
  u8  state;
  u16 handle;
  u32 packets;
} hci_conn_t;

typedef struct bt_state {
  hci_conn_t  conns[2];
  hci_conn_t *le_conn;
  hci_conn_t *bredr_conn;
  u8 filter_policy;
} bt_state_t;

#define queue_entry_append_event(_q, _opc, _type, _size)            \
  u32             _total_size;                                      \
  u8             *_payload;                                         \
  bt_hci_evt_hdr *_evt;                                             \
  _type          *evt_params;                                       \
  _total_size = 1 + sizeof(*_evt) + _size;                          \
  _payload = queue_entry_alloc_message(_q, _total_size);            \
  _payload[0] = BT_H4_EVT_PKT;                                      \
  _evt = (bt_hci_evt_hdr *)&_payload[1];                            \
  _evt->evt = _opc;                                                 \
  _evt->plen = _size;                                               \
  evt_params = (_type *)_evt->params;

#define queue_entry_append_le_event(_q, _opc, _type, _size)         \
  u32             _total_size;                                      \
  u8             *_payload;                                         \
  bt_hci_evt_hdr *_evt;                                             \
  _type          *evt_params;                                       \
  _total_size = 2 + sizeof(*_evt) + _size;                          \
  _payload = queue_entry_alloc_message(_q, _total_size);            \
  _payload[0] = BT_H4_EVT_PKT;                                      \
  _evt = (bt_hci_evt_hdr *)&_payload[1];                            \
  _evt->evt = BT_HCI_EVT_LE_META_EVENT;                             \
  _evt->plen = 1 + _size;                                           \
  _evt->params[0] = _opc;                                           \
  evt_params = (_type *)&_evt->params[1];

#define queue_entry_append_l2cap(_q, _handle, _cid, _type, _size)   \
  u32             _total_size;                                      \
  u8             *_payload;                                         \
  bt_hci_acl_hdr *_acl;                                             \
  bt_l2cap_hdr   *_l2cap;                                           \
  _type          *l2cap_params;                                     \
  _total_size = 1 + sizeof(*_acl) + sizeof(*_l2cap) + _size;        \
  _payload = queue_entry_alloc_message(_q, _total_size);            \
  _payload[0] = BT_H4_ACL_PKT;                                      \
  _acl = (bt_hci_acl_hdr *)&_payload[1];                            \
  _acl->handle = hci_handle_pack(_handle, PB_START);                \
  _acl->dlen = sizeof(*_l2cap) + _size;                             \
  _l2cap = (bt_l2cap_hdr *)_acl->data;                              \
  _l2cap->len = _size;                                              \
  _l2cap->cid = _cid;                                               \
  l2cap_params = (_type *)_l2cap->data;

#endif