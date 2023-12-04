#ifndef CHAR_BUZZER_H
#define CHAR_BUZZER_H

#include "hw/char/serial.h"
#include "sysemu/char.h"

#define BUZZER_BUFFER_SIZE 65536
#define BUZZER_MAX_TX_WORKS 4

typedef struct Txork {
    uint8_t buf[BUZZER_BUFFER_SIZE];
    size_t len;
    size_t pos;
}TxWork;

typedef TxWork RxWork;

typedef struct BuzzerChardev{
    Chardev parent;
    int efd;
    Chardev* chr;
    QIOChannel *ioc;
    size_t max_size;
    RxWork rx_work;
    TxWork tx_works[BUZZER_MAX_TX_WORKS];
    uint8_t tx_cur, tx_end;
    QEMUTimer* recv_timer;
    QEMUTimer* send_timer;
    QEMUBH* bh;
} BuzzerChardev;

#define BUZZER_CHARDEV(obj)                                    \
    OBJECT_CHECK(BuzzerChardev, (obj), TYPE_CHARDEV_BUZZER)

typedef int PacketHandler(uint8_t *buf, int size);

void char_buzzer_reset(void);

void buzzer_register_packet_handler(PacketHandler* handler);

#endif