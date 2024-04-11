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
#include "afl/afl-fuzz.h"
#include "afl/debug.h"
#include "bluetooth/bluetooth.h"

#include <sys/uio.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/types.h>

/* Buzzer chardev backend to send/recv HCI packets */

static BuzzerChardev* buzzer_char = NULL;
static PacketHandler* packet_handler = NULL;

static int char_buzzer_read_poll(void *opaque) 
{
    Chardev *chr = CHARDEV(opaque);
    BuzzerChardev *d = BUZZER_CHARDEV(opaque);

    d->max_size = qemu_chr_be_can_write(chr);
    return d->max_size;
}

void __hot host_send(uint8_t* buf, int len)
{
    int fd = buzzer->h2c_data_pipe[1];
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len
    };
    if (unlikely(writev(fd, &iov, 1) == -1)) {
        FATAL("Host send fail: %s", strerror(errno));
    }
}

int __hot host_recv(uint8_t* buf, int tmout_ms)
{
    int sret, fd;
    fd_set fdset;
    struct timeval timeout;

    fd = buzzer->c2h_data_pipe[0];
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);

    timeout.tv_sec = (tmout_ms / 1000);
    timeout.tv_usec = (tmout_ms % 1000) * 1000;

    do {
        sret = select(fd + 1, &fdset, NULL, NULL, &timeout);
    } while (sret < 0 && errno == EINTR);

    if (unlikely(sret < 0)) {
        FATAL("Select fail: %s", strerror(errno));
    }

    if (sret == 0) {
        return -2;
    }

    return read(fd, buf, BZ_BUF_MAX);
}

void __hot host_recv_drain(uint8_t *buf) 
{
    int ret = 0;
    do {
        ret = host_recv(buf, 0);
    } while (ret != -2);
}

static int char_buzzer_write(Chardev *chr, const uint8_t *buf, int len)
{
    // char buzzer is writing data to the outside
    BuzzerChardev *d = BUZZER_CHARDEV(chr);

    // for (int i = 0 ; i < len; ++i) {
    //     d->rx_work.buf[d->rx_work.pos + i] = buf[i];
    // }
    // d->rx_work.pos += len;
    // timer_mod(d->recv_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) 
    //     + s->char_transmit_time * BZ_RECV_TMOUT_SCALE);

	bt_hci_cmd_hdr *cmd_hdr;
	bt_hci_acl_hdr *acl_hdr;
	bt_hci_sco_hdr *sco_hdr;
	bt_hci_iso_hdr *iso_hdr;
	uint16_t pktlen;

    memcpy(d->host_buf + d->host_len, buf, len);

	if (len < 0) {
		return len;
	}

	d->host_len += len;

process_packet:
	if (d->host_len < 1)
		return len;

	switch (d->host_buf[0]) {
	case BT_H4_CMD_PKT:
		if (d->host_len < 1 + sizeof(*cmd_hdr)) {
			return len;
        }
		cmd_hdr = (void *) (d->host_buf + 1);
		pktlen = 1 + sizeof(*cmd_hdr) + cmd_hdr->plen;
		break;

	case BT_H4_ACL_PKT:
		if (d->host_len < 1 + sizeof(*acl_hdr)) {
			return len;
        }
		acl_hdr = (void *) (d->host_buf + 1);
		pktlen = 1 + sizeof(*acl_hdr) + acl_hdr->dlen;
		break;

	case BT_H4_SCO_PKT:
		if (d->host_len < 1 + sizeof(*sco_hdr)) {
			return len;
        }
		sco_hdr = (void *) (d->host_buf + 1);
		pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;
		break;

	case BT_H4_ISO_PKT:
		if (d->host_len < 1 + sizeof(*iso_hdr)) {
			return len;
        }
		iso_hdr = (void *) (d->host_buf + 1);
		pktlen = 1 + sizeof(*iso_hdr) + iso_hdr->dlen;
		break;

	default:
        d->host_len = 0;
		return len;
	}

	if (d->host_len < pktlen) {
		return len;
    }

	// if (emulate_ecc)
	// 	host_emulate_ecc(proxy, proxy->host_buf, pktlen);
	// else

    // if (buzzer->exec_speed_abnormal) {
    //     static int cnt = 0;
    // qemu_hexdump(d->host_buf, stderr, "char buzzer send", pktlen);
    //     ++cnt;
    //     if (cnt > 10) {
    //         cnt = 0;
    //         return FSRV_RUN_CRASH;
    //     }
    // }

	host_send(d->host_buf, pktlen);
    // qio_channel_write(d->ioc_out, d->host_buf, pktlen, NULL);

	if (d->host_len > pktlen) {
		memmove(d->host_buf, d->host_buf + pktlen, d->host_len - pktlen);
		d->host_len -= pktlen;
		goto process_packet;
	}

	d->host_len = 0;

    return len;
}

static gboolean char_buzzer_read(QIOChannel *chan, GIOCondition cond, void *opaque) 
{
    // char buzzer is reading from the outside
    Chardev *chr = CHARDEV(opaque);
    BuzzerChardev* d = BUZZER_CHARDEV(opaque);
    // SerialState* s = d->parent.be->opaque;
    // TxWork* tx_work = &d->tx_works[d->tx_cur];
    static uint8_t buf[1024];
    ssize_t ret;
    int len;

    len = sizeof(buf);
    if (len > d->max_size) {
        len = d->max_size;
    }
    if (len == 0) {
        return TRUE;
    }

    ret = qio_channel_read(chan, (gchar *)buf, len, NULL);
    // qemu_hexdump(buf, stdout, "char buzzer recv", ret);
    qemu_chr_be_write(chr, buf, ret);

    return TRUE;
}

static void char_buzzer_trigger_send(void) 
{
    uint64_t send = 1;
    write(buzzer_char->efd, &send, sizeof(send));
}

// static void char_buzzer_recv_complete(void* opaque) 
// {
//     BuzzerChardev *d = BUZZER_CHARDEV(opaque);  
//     RxWork* rx_work = &d->rx_work;
//     timer_del(d->recv_timer);
//     // qemu_hexdump(rx_work->buf, stdout, "recv", rx_work->pos);
//     buzzer_on_serial_recv(rx_work->buf, rx_work->pos);
//     rx_work->pos = 0;
// }

// static void char_buzzer_send_complete(void* opaque) 
// {
//     BuzzerChardev* d = BUZZER_CHARDEV(opaque);
//     timer_del(d->send_timer);
//     d->tx_cur = (d->tx_cur + 1) % BUZZER_MAX_TX_WORKS;
//     if (d->tx_cur != d->tx_end)
//         char_buzzer_trigger_send();
// }

static void char_buzzer_update_read_handler(Chardev *chr, GMainContext *context) 
{
    BuzzerChardev *d = BUZZER_CHARDEV(chr);
    d->chr = chr;
    remove_fd_in_watch(chr, NULL);
    chr->fd_in_tag = io_add_watch_poll(chr, d->ioc_in,
                                           char_buzzer_read_poll,
                                           char_buzzer_read, chr,
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

void char_buzzer_reset(void) 
{
    // uint64_t temp;
    // buzzer_char->rx_work.pos = buzzer_char->rx_work.len = 0;
    // buzzer_char->tx_cur = buzzer_char->tx_end = 0;
    // read(buzzer_char->efd, &temp, sizeof(temp));
    // timer_del(buzzer_char->send_timer);
    // timer_del(buzzer_char->recv_timer);
            host_recv_drain(buzzer->mbuf);

    buzzer_char->host_len = 0;
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

static GSource *char_buzzer_add_watch(Chardev *chr, GIOCondition cond)
{
    BuzzerChardev *s = BUZZER_CHARDEV(chr);
    return qio_channel_create_watch(s->ioc_out, cond);
}

static void char_buzzer_init(Object* obj) 
{
    BuzzerChardev* d = BUZZER_CHARDEV(obj);
    // d->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    // d->rx_work.pos = d->rx_work.len = 0;
    // d->tx_cur = d->tx_end = 0;

    d->ioc_in = QIO_CHANNEL(qio_channel_file_new_fd(buzzer->c2h_data_pipe[0]));
    qio_channel_set_name(QIO_CHANNEL(d->ioc_in), "chardev-buzzer-ioc-in");
    d->ioc_out = QIO_CHANNEL(qio_channel_file_new_fd(buzzer->h2c_data_pipe[1]));
    qio_channel_set_name(QIO_CHANNEL(d->ioc_out), "chardev-buzzer-ioc-out");

    // d->send_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, (QEMUTimerCB *)char_buzzer_send_complete, d);
    // d->recv_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, (QEMUTimerCB *)char_buzzer_recv_complete, d);

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
    cc->chr_add_watch = char_buzzer_add_watch;
    cc->chr_write = char_buzzer_write;
    cc->chr_update_read_handler = char_buzzer_update_read_handler;
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
