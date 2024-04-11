#ifndef _HCI_FORMAT_H
#define _HCI_FORMAT_H

#include "qemu/compiler.h"
#include "qemu/osdep.h"

#define HCI_NODE_MAX 255

typedef struct hci_cmd_format {
  uint16_t opcode;
  uint32_t size;
  uint32_t rsp_size;
  int bd_addr_offset;
  int handle_offset;
  int rsp_status_offset;
  int rsp_bd_addr_offset;
  int rsp_handle_offset;
} hci_cmd_format_t;

typedef struct hci_evt_format {
  uint8_t opcode;
  uint8_t le;
  uint32_t size;
  int status_offset;
  int bd_addr_offset;
  int handle_offset;
} hci_evt_format_t;

typedef struct hci_node {
  uint16_t opcode1;
  uint16_t opcode2;
  uint16_t opcode3;
  uint16_t opcode4;
} __attribute__((packed)) hci_node_t;

typedef uint64_t hci_edge_t;

extern GArray *hci_cmds;
extern GArray *hci_evts;
extern GArray *hci_le_evts;
extern GHashTable *hci_cmd_map;
extern GHashTable *hci_evt_map;
extern GHashTable *hci_le_evt_map;
extern GHashTable *hci_rsp_map;

extern GArray *hci_iut_evts;
extern GArray *hci_iut_le_evts;

extern uint8_t event_mask[];
extern uint8_t event_mask_page2[];
extern uint8_t le_event_mask[];

hci_cmd_format_t *get_hci_cmd(uint16_t opcode);
hci_evt_format_t *get_hci_evt(uint8_t opcode);
hci_evt_format_t *get_hci_le_evt(uint8_t opcode);
hci_evt_format_t *get_hci_cmd_rsp(uint16_t opcode);

hci_cmd_format_t *get_hci_cmd_by_index(uint32_t index);
hci_evt_format_t *get_hci_evt_by_index(uint32_t index);
hci_evt_format_t *get_hci_le_evt_by_index(uint32_t index);
hci_evt_format_t *get_hci_iut_evt_by_index(uint32_t index);
hci_evt_format_t *get_hci_iut_le_evt_by_index(uint32_t index);

void add_hci_iut_evt(uint8_t opcode);
void add_hci_iut_le_evt(uint8_t opcode);

void show_iut_evts(void);
void show_iut_le_evts(void);

uint32_t hci_cmd_cnt(void);
uint32_t hci_evt_cnt(void);
uint32_t hci_le_evt_cnt(void);
uint32_t hci_iut_evt_cnt(void);
uint32_t hci_iut_le_evt_cnt(void);

void update_event_mask_map(void);
void update_event_mask_page2_map(void);
void update_le_event_mask_map(void);

uint32_t hci_node(uint8_t *message);
uint32_t hci_edge(uint32_t src, uint32_t dest);

#define HCI_COMMANDS_FOREACH(block)                                            \
  do {                                                                         \
    int i = 0, n = hci_cmd_cnt();                                              \
    for (; i < n; ++i) {                                                       \
      hci_cmd_format_t *fmt = get_hci_cmd_by_index(i);                         \
      { block }                                                                \
    }                                                                          \
  } while (0);

#define HCI_LE_EVENTS_FOREACH(block)                                           \
  do {                                                                         \
    int i = 0, n = hci_le_evt_cnt();                                           \
    for (; i < n; ++i) {                                                       \
      hci_evt_format_t *fmt = get_hci_le_evt_by_index(i);                      \
      { block }                                                                \
    }                                                                          \
  } while (0);

#define HCI_EVENTS_FOREACH(block)                                              \
  do {                                                                         \
    int i = 0, n = hci_evt_cnt();                                              \
    for (; i < n; ++i) {                                                       \
      hci_evt_format_t *fmt = get_hci_evt_by_index(i);                         \
      { block }                                                                \
    }                                                                          \
  } while (0);

#endif