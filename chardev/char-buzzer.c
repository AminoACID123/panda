#include "qemu/osdep.h"
#include "char-buzzer.h"
#include "chardev/char-io.h"
#include "qemu/sockets.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "sysemu/char.h"
#include "io/channel-file.h"
#include "panda/debug.h"
#include "panda/buzzer.h"
#include "afl/debug.h"

#include <sys/uio.h>
#include <sys/eventfd.h>

/* Buzzer chardev backend to send/recv HCI packets */

static BuzzerChardev* buzzer_char = NULL;
static PacketHandler* packet_handler = NULL;

static int char_buzzer_poll_fe(void *opaque) {
    Chardev *chr = CHARDEV(opaque);
    BuzzerChardev *d = BUZZER_CHARDEV(opaque);

    d->max_size = qemu_chr_be_can_write(chr);
    return d->max_size;
}

static int char_buzzer_recv(Chardev *chr, const uint8_t *buf, int len)
{
    BuzzerChardev *d = BUZZER_CHARDEV(chr);
    SerialState* s = chr->be->opaque;

    for (int i = 0 ; i < len; ++i) {
        d->rx_work.buf[d->rx_work.pos + i] = buf[i];
    }
    d->rx_work.pos += len;
    timer_mod(d->recv_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->char_transmit_time * BZ_RECV_TMOUT_SCALE);
    return len;
}

static gboolean char_buzzer_write_fe(QIOChannel *chan, GIOCondition cond, void *opaque) 
{
    BuzzerChardev* d = BUZZER_CHARDEV(opaque);
    SerialState* s = d->parent.be->opaque;
    TxWork* tx_work = &d->tx_works[d->tx_cur];

    int n1 = d->max_size;
    int n2 = tx_work->len - tx_work->pos;
    int len = n1 < n2 ? n1 : n2;

    if (len == 0) {
        return true;
    }

    qemu_chr_be_write(&d->parent, &tx_work->buf[tx_work->pos], len);
    tx_work->pos += len;


    if (tx_work->pos == tx_work->len) {
        uint64_t temp;
        read(d->efd, &temp, sizeof(temp));
        timer_mod(d->send_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->char_transmit_time * 50);
    }

    return true;
}

static void char_buzzer_trigger_send(void) 
{
    uint64_t send = 1;
    write(buzzer_char->efd, &send, sizeof(send));
}

static void char_buzzer_recv_complete(void* opaque) 
{
    BuzzerChardev *d = BUZZER_CHARDEV(opaque);  
    RxWork* rx_work = &d->rx_work;
    timer_del(d->recv_timer);
    // qemu_hexdump(rx_work->buf, stdout, "recv", rx_work->pos);
    buzzer_on_serial_recv(rx_work->buf, rx_work->pos);
    rx_work->pos = 0;
}

static void char_buzzer_send_complete(void* opaque) 
{
    BuzzerChardev* d = BUZZER_CHARDEV(opaque);
    timer_del(d->send_timer);
    d->tx_cur = (d->tx_cur + 1) % BUZZER_MAX_TX_WORKS;
    if (d->tx_cur != d->tx_end)
        char_buzzer_trigger_send();
}

static void char_buzzer_update_read_handler(Chardev *chr, GMainContext *context) 
{
    BuzzerChardev *d = BUZZER_CHARDEV(chr);
    d->chr = chr;
    // remove_fd_in_watch(chr, NULL);
    chr->fd_in_tag = io_add_watch_poll(chr, d->ioc,
                                           char_buzzer_poll_fe,
                                           char_buzzer_write_fe, chr,
                                           context);
}

void char_buzzer_send_packet_v(const struct iovec *iov, int iovcnt) 
{
    TxWork* tx_work;
    tx_work = &buzzer_char->tx_works[buzzer_char->tx_end];
    tx_work->pos = tx_work->len = 0;
    for (int i = 0; i < iovcnt; ++i) {
        memcpy(&tx_work->buf[tx_work->len], iov[i].iov_base, iov[i].iov_len);
        tx_work->len += iov[i].iov_len;
    }

    buzzer_char->tx_end = (buzzer_char->tx_end + 1) % BUZZER_MAX_TX_WORKS;
    if (buzzer_char->tx_end == ((buzzer_char->tx_cur + 1) % BUZZER_MAX_TX_WORKS))
        char_buzzer_trigger_send();

    // qemu_hexdump((char*)tx_work->buf, stdout, "send", tx_work->len);
}

void char_buzzer_send_packet(uint8_t* data, int len) 
{
    TxWork* tx_work;    
    tx_work = &buzzer_char->tx_works[buzzer_char->tx_end];
    tx_work->pos = tx_work->len = 0;
    memcpy(tx_work->buf, data, len);
    tx_work->len = len;
    buzzer_char->tx_end = (buzzer_char->tx_end + 1) % BUZZER_MAX_TX_WORKS;

    if (buzzer_char->tx_end == ((buzzer_char->tx_cur + 1) % BUZZER_MAX_TX_WORKS))
        char_buzzer_trigger_send();
    
    // qemu_hexdump((char*)tx_work->buf, stdout, "send", tx_work->len);
}

void buzzer_register_packet_handler(PacketHandler* handler) 
{
    packet_handler = handler;
}

// void buzzer_register_packet_send_handler(PacketSendHandler* handler) {
//     BuzzerChardev* d = buzzer_chr;
//     d->packet_send_handler = handler;
// }

void char_buzzer_reset(void) {
    if (buzzer_char) {
        uint64_t temp;
        buzzer_char->rx_work.pos = buzzer_char->rx_work.len = 0;
        buzzer_char->tx_cur = buzzer_char->tx_end = 0;
        read(buzzer_char->efd, &temp, sizeof(temp));
        timer_del(buzzer_char->send_timer);
        timer_del(buzzer_char->recv_timer);
    }
}

/*
static void char_buzzer_vmstate_change(void *opaque, int running, RunState state) {
    uint64_t temp;
    BuzzerChardev* d = opaque;
    if (!running) {
        d->rx_work.pos = d->rx_work.len = 0;
        d->tx_cur = d->tx_end = 0;
        read(d->efd, &temp, sizeof(temp));
        timer_del(d->send_timer);
        timer_del(d->recv_timer);
    }
}
*/

static void char_buzzer_init(Object* obj) 
{
    BuzzerChardev* d = BUZZER_CHARDEV(obj);
    d->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    d->rx_work.pos = d->rx_work.len = 0;
    d->tx_cur = d->tx_end = 0;

    d->ioc = QIO_CHANNEL(qio_channel_file_new_fd(d->efd));
    qio_channel_set_name(QIO_CHANNEL(d->ioc), "chardev-buzzer-ioc");

    d->send_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, (QEMUTimerCB *)char_buzzer_send_complete, d);
    d->recv_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, (QEMUTimerCB *)char_buzzer_recv_complete, d);

    if (buzzer_char == NULL) {
        buzzer_char = d;
    }
    else {
        FATAL("Can only have one buzzer chardev instance\n");
    }

    // qemu_add_vm_change_state_handler(char_buzzer_vmstate_change, d);
}

static void char_buzzer_class_init(ObjectClass *oc, void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);
    cc->chr_write = char_buzzer_recv;
    cc->chr_update_read_handler = char_buzzer_update_read_handler;
    // cc->chr_update_read_handler
}

static void char_buzzer_finalize(Object *obj)
{
    // BuzzerChardev *d = BUZZER_CHARDEV(obj);
}


static const TypeInfo char_buzzer_type_info = {
    .name = TYPE_CHARDEV_BUZZER,
    .parent = TYPE_CHARDEV,
    .class_init = char_buzzer_class_init,
    .instance_size = sizeof(BuzzerChardev),
    .instance_init = char_buzzer_init,
    .instance_finalize = char_buzzer_finalize,
};

static void register_types(void)
{
    type_register_static(&char_buzzer_type_info);
}

type_init(register_types);
