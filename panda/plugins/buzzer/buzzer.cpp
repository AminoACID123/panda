/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Anzi Xu               tleek@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "afl/debug.h"
#include "panda/plugin.h"
// #include "panda/buzzer.h"
#include "taint2/taint2.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

static bool taint_sym_enabled = false;
uint32_t taint_lablel = 0xdeadbeef;
uint32_t taint_index = 0;

enum : uint32_t {
    TAINT_LABLE_H4_FLAG,
    TAINT_LABLE_HCI_LEN,
    TAINT_LABLE_EVT_OPCODE,
    TAINT_LABLE_CMD_OPCODE
};

enum taint_state_t: uint8_t {
    TAINT_STATE_H4_FLAG,
    TAINT_STATE_HCI_LEN,
    TAINT_STATE_EVT_OPCODE,
    TAINT_STATE_EVT_LEN,
    TAINT_STATE_CMD_OPCODE,
    TAINT_STATE_STOP
};

Addr make_iaddr(uint64_t a)
{
    Addr ia;
    ia.typ = IADDR;
    ia.val.ia = a;
    ia.off = 0;
    ia.flag = (AddrFlag)0;
    return ia;
}

void buzzer_on_taint_change(Addr a, uint64_t size) {
    // fprintf(stderr, "Type %d, Addr %llx, Offset %x, Size %ld\n",a.typ, a.val, a.off, size);
    // auto loc = shadow->query_loc(a);
    // OKF("%s", loc.first->name());
    // loc.first->query_full(loc.second);
}

void buzzer_on_branch(Addr a, uint64_t size, bool from_helper, bool *tainted) {
    // a is an llvm reg
    assert (a.typ == LADDR);
    // count number of tainted bytes on this reg
    uint32_t num_tainted = 0;
    Addr ao = a;
    for (uint32_t o = 0; o < size; o++) {
        ao.off = o;
        num_tainted += (taint2_query(ao) != 0);
    }
    if (num_tainted > 0) {
        *tainted = true;
    }
}

void buzzer_on_taint_prop(Addr dest, Addr src, uint64_t size) {
    
}

void buzzer_serial_receive(CPUState *cpu, target_ptr_t fifo_addr, uint8_t value) {

    static int taint_index = 0;

    if (!taint_sym_enabled) {
        taint2_enable_sym();
        taint_sym_enabled = true;
    }

    // if ((buzzer_state.analyze_task == EXTRACT_EVENTS && taint_index == 1) 
    //     || (buzzer_state.analyze_task == EXTRACT_LE_EVENTS && taint_index == 3) ) {
    //     OKF("%x\n", fifo_addr);
    //     taint2_label_io(fifo_addr, TAINT_LABLE_EVT_OPCODE);
    //     taint2_sym_label_addr(make_iaddr(fifo_addr), 0, taint_lablel);
    // }
    // else {
    //     taint2_delete_io(fifo_addr);
    // }

    taint_index++;
}

void buzzer_serial_read(CPUState *cpu, target_ptr_t fifo_addr, uint32_t port_addr,
                 uint8_t value) {

    if (!taint2_enabled()) {
        return;
    }
    
#ifdef TARGET_I386
    // Copy taint from the IO shadow into the EAX register.
    taint2_labelset_io_iter(fifo_addr,
                            [](uint32_t elt, void *unused) {
                                taint2_label_reg_additive(R_EAX, 0, elt);
                                return 0;
                            },
                            NULL);

    Addr iaddr = make_iaddr(fifo_addr);
    if (taint2_sym_query(iaddr)) {
        OKF("copy eax %x", value);
        taint2_sym_label_reg(R_EAX, 0, taint_lablel);
    }
    else {
        taint2_delete_reg(R_EAX, 0);
        taint2_sym_delete_reg(R_EAX, 0);
    }

#endif
    return;
}

bool init_plugin(void *self) {

    panda_require("taint2");
    assert(init_taint2_api());

    panda_cb pcb;

    pcb.replay_serial_receive = buzzer_serial_receive;
    panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_RECEIVE, pcb);

    pcb.replay_serial_read = buzzer_serial_read;
    panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_READ, pcb);

    // pcb.after_machine_init = after_machine_init;
    // panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);

    // PPP_REG_CB("buzzer", on_taint_prop, buzzer_on_taint_prop);
    // PPP_REG_CB("taint2", on_taint_change, buzzer_on_taint_change);
    PPP_REG_CB("taint2", on_branch2, buzzer_on_branch);

    return true;
}

void uninit_plugin(void *self) { }
