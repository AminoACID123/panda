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

  u8 state;
  u16 handle;
  u32 packets;

}__attribute__((packed)) hci_conn_t;

typedef struct bt_state {

  hci_conn_t conns[2];
  hci_conn_t* le_conn;
  hci_conn_t* bredr_conn;
  
}__attribute__((packed)) bt_state_t;


#endif