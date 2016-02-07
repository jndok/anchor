/*
 *      _  _  _                          _
 *     | |(_)| |                        | |
 *     | | _ | |__    __ _  _ __    ___ | |__    ___   _ __
 *     | || || '_ \  / _` || '_ \  / __|| '_ \  / _ \ | '__|
 *     | || || |_) || (_| || | | || (__ | | | || (_) || |
 *     |_||_||_.__/  \__,_||_| |_| \___||_| |_| \___/ |_|
 *
 *                             ***
 *
 *  Keep in mind that this code is experimental and has been wrote in
 *  a few hours, meaning not many tests have been performed and code
 *  is certainly not perfect.
 *  This should be the best approach to dynamic function hooking on OSX,
 *  since it basically has no overhead on the hooked task and seems to
 *  perform well.
 *
 *  Updates will come!
 */

//
//  libanchor.h
//  libanchor
//
//  Created by jndok on 06/02/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#ifndef libanchor_h
#define libanchor_h

#define DEBUG_LOG_SET
#define __dbg(msg, ...) fprintf(stderr, "[%s]: " msg "\n", __func__, ##__VA_ARGS__)

enum codes {
    ANCHOR_INIT_SUCCESS=0,
    ANCHOR_INIT_FAILURE,
    ANCHOR_LISTENER_FAIL
};

#define HOOK_BYTE 0xCC /* mimicking breakpoints */

#define __WRITE_BYTE(func, byte) \
    vm_protect(mach_task_self(), (vm_address_t)func, 4, 0, VM_PROT_ALL);    \
    *(uint8_t*)func = (uint8_t)byte;

/* tried to keep these as clean as possible.. */
#pragma mark HOOK TABLE MACROS

#define ALLOC_HOOK_TABLE_ENTRY(name)                hook_table_t *name = calloc(1, sizeof(hook_table_t))
#define ALLOC_INIT_HOOK_TABLE_ENTRY(name, o, h) \
    ALLOC_HOOK_TABLE_ENTRY(name);   \
    name->__hook=(void*)h;  \
    name->__original=(void*)o;  \

#define INSERT_HOOK(head, entry)                    SLIST_INSERT_HEAD(head, entry, table)
#define REMOVE_HOOK(head, entry)                    SLIST_REMOVE(head, entry, hook_table, table);

#define HOOK_TABLE_ITERATE(head)  \
    hook_table_entry_t *curr=NULL;  \
    SLIST_FOREACH(curr, head, table)

#define HOOK_TABLE_ORIGINAL_LOOKUP(head, o, entry) {    \
    HOOK_TABLE_ITERATE(head) {    \
        if ((uint64_t)curr->__original == (uint64_t)o) {    \
            entry = curr;  \
        }   \
    }   \
}

#define HOOK_TABLE_HOOK_LOOKUP(head, h, entry) {    \
    HOOK_TABLE_ITERATE(head) {    \
        if ((uint64_t)curr->__hook == (uint64_t)h) {    \
            entry = curr;  \
        }   \
    }   \
}

/* XXX: unstable!!! */
#pragma mark STATE CONTROL MACROS

#define STATE_WRITE_RAX(state, what)    (state)->uts.ts64.__rax = (uint64_t)what
#define STATE_WRITE_RBX(state, what)    (state)->uts.ts64.__rbx = (uint64_t)what
#define STATE_WRITE_RCX(state, what)    (state)->uts.ts64.__rcx = (uint64_t)what
#define STATE_WRITE_RDX(state, what)    (state)->uts.ts64.__rdx = (uint64_t)what
#define STATE_WRITE_RSI(state, what)    (state)->uts.ts64.__rsi = (uint64_t)what
#define STATE_WRITE_RDI(state, what)    (state)->uts.ts64.__rdi = (uint64_t)what

#define STATE_WRITE_RIP(state, what)    (state)->uts.ts64.__rip = (uint64_t)what

#define STATE_SET_ARG1(state, arg)      STATE_WRITE_RDI(state, arg)
#define STATE_SET_ARG2(state, arg)      STATE_WRITE_RSI(state, arg)
#define STATE_SET_ARG3(state, arg)      STATE_WRITE_RDX(state, arg)
#define STATE_SET_ARG4(state, arg)      STATE_WRITE_RCX(state, arg)

#define STATE_HIJACK_RIP(state, where)  (state)->uts.ts64.__rip = (uint64_t)&where;

#pragma mark FUNCTIONS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>

#include <mach/mach.h>

boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

__attribute__((aligned(64))) typedef struct hook_table {
    SLIST_ENTRY(hook_table) table;
    void *__original;
    void *__hook;
    /* x86_thread_state_t *state; */ // still unstable
    uint8_t stolen_byte;
} hook_table_t;

typedef SLIST_HEAD(hook_table_head, hook_table) hook_table_head_t;
typedef hook_table_t hook_table_entry_t;

hook_table_head_t *get_hook_table_head(void);

void __anchor_set_hook(void *original, void *hook);
void __anchor_unset_hook(void *original);

uint16_t __anchor_init(void);
__unused static void *__init_handler(void *arg);

/* apis are weak, expand those to your needs */
kern_return_t __get_thread_state(mach_port_t thread, x86_thread_state_t *state);
kern_return_t __set_thread_state(mach_port_t thread, x86_thread_state_t *state);

#endif /* libanchor_h */
