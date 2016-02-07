//
//  libanchor.c
//  libanchor
//
//  Created by jndok on 06/02/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include "libanchor.h"

hook_table_head_t head = SLIST_HEAD_INITIALIZER(head);

__attribute__((always_inline)) hook_table_head_t *get_hook_table_head(void)
{
    return &head;
}

void __anchor_set_hook(void *original, void *hook)
{
    if ((original == NULL) || (hook == NULL)) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Cannot throw hooks to NULL, or hook with NULL.");
#endif
        return;
    }
    
    HOOK_TABLE_ITERATE(&head) {
        if ((uint64_t)curr->__original == (uint64_t)original) {
#ifdef DEBUG_LOG_SET
            __dbg("(!) Unable to set hook! Function %#016llx already hooked.", (uint64_t)curr->__original);
#endif
            return;
        }
    }
    
    ALLOC_INIT_HOOK_TABLE_ENTRY(hook_entry, original, hook);
    hook_entry->stolen_byte = *(uint8_t*)original;
    
    __WRITE_BYTE(original, HOOK_BYTE);
    
    INSERT_HOOK(get_hook_table_head(), hook_entry);
}

void __anchor_unset_hook(void *original)
{
    if (original == NULL) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Cannot unhook NULL.");
#endif
        return;
    }
    
    hook_table_entry_t *entry=NULL;
    HOOK_TABLE_ORIGINAL_LOOKUP(&head, original, entry);
    
    if (!entry) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Unable to remove hook! Function %#016llx is not hooked.", (uint64_t)original);
#endif
        return;
    }
    
    __WRITE_BYTE(original, entry->stolen_byte);
    
    REMOVE_HOOK(&head, entry);
    
    free(entry);
}

uint16_t __anchor_init(void)
{
    SLIST_INIT(&head);
    
    kern_return_t kr;
    int32_t pthread_err;
    mach_port_t exception_port = MACH_PORT_NULL;
    
    pthread_t handler_thread;
    
    mach_msg_type_number_t maskCount = 1;
    exception_mask_t mask;
    exception_handler_t handler;
    exception_behavior_t behavior;
    thread_state_flavor_t flavor;
    
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
    if (kr != KERN_SUCCESS) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Unable to allocate exception port! Error: %#x (%s)", kr, mach_error_string(kr));
#endif
        return ANCHOR_INIT_FAILURE;
    }
    
    kr = mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Unable to set SEND port right for exception port! Error: %#x (%s)", kr, mach_error_string(kr));
#endif
        return ANCHOR_INIT_FAILURE;
    }
    
    kr = task_get_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, &mask, &maskCount, &handler, &behavior, &flavor);
    if (kr != KERN_SUCCESS) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Unable to get task exception ports! Error: %#x (%s)", kr, mach_error_string(kr));
#endif
        return ANCHOR_INIT_FAILURE;
    }
    
    pthread_err = pthread_create(&handler_thread, NULL, __init_handler, &exception_port);
    if (pthread_err != 0x0) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Unable to initialize listener thread! Error: %#x", pthread_err);
#endif
        return ANCHOR_INIT_FAILURE;
    }
    
    pthread_detach(handler_thread);
    
    kr = task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, exception_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, flavor);
    if (kr != KERN_SUCCESS) {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Unable to set task exception ports! Error: %#x (%s)", kr, mach_error_string(kr));
#endif
        return ANCHOR_INIT_FAILURE;
    }
    
    return ANCHOR_INIT_SUCCESS;
}

static void *__init_handler(void *arg)  /* msg listener */
{
    
    mach_port_t exception_port = *(mach_port_t *)arg;
    kern_return_t kr;
    
    while(1) {
        if ((kr = mach_msg_server_once(mach_exc_server, 4096, exception_port, 0)) != KERN_SUCCESS) {
#ifdef DEBUG_LOG_SET
            __dbg("(!) Listener failed on mach_msg_server_once()! Error: %#x (%s)", kr, mach_error_string(kr));
#endif
            exit(ANCHOR_LISTENER_FAIL);
        }
    }
    
    return NULL;
}

kern_return_t __get_thread_state(mach_port_t thread, x86_thread_state_t *state)
{
    
    kern_return_t kr;
    unsigned int cnt = x86_THREAD_STATE_COUNT;
    
    if((kr = thread_get_state(thread, x86_THREAD_STATE, (thread_state_t)state, &cnt)) != KERN_SUCCESS)
        return KERN_FAILURE;
    
    return KERN_SUCCESS;
}

kern_return_t __set_thread_state(mach_port_t thread, x86_thread_state_t *state)
{
    
    kern_return_t kr;
    
    if((kr = thread_set_state(thread, x86_THREAD_STATE, (thread_state_t)state, x86_THREAD_STATE_COUNT)) != KERN_SUCCESS)
        return KERN_FAILURE;
    
    return KERN_SUCCESS;
}

kern_return_t catch_mach_exception_raise(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t type, exception_data_t code, mach_msg_type_number_t code_count) {
    
    x86_thread_state_t tstate;
    __get_thread_state(thread, &tstate);
    
    uint64_t orig = (tstate.uts.ts64.__rip) - 0x1;
    uint64_t hook=0x0;
    
    HOOK_TABLE_ITERATE(&head) { /* dispatch loop */
        if ((uint64_t)curr->__original == orig) {
#ifdef DEBUG_LOG_SET
            __dbg("(+) Function %#016llx has been found in hook table! Redirecting control flow...", (uint64_t)curr->__original);
#endif
            hook = (uint64_t)curr->__hook;
            break;
        }
    }
    
    if (hook) {
        tstate.uts.ts64.__rip = hook;
        
        // curr->state=&tstate;
        __set_thread_state(thread, &tstate);
        
        return KERN_SUCCESS;
    } else {
#ifdef DEBUG_LOG_SET
        __dbg("(!) Function %#016llx was not found in hook table! Breakpoint wasn't probably set by us.", (uint64_t)curr->__original);
#endif
    }
    
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state
(
	mach_port_t exception_port,
	exception_type_t exception,
	const mach_exception_data_t code,
	mach_msg_type_number_t codeCnt,
	int *flavor,
	const thread_state_t old_state,
	mach_msg_type_number_t old_stateCnt,
	thread_state_t new_state,
	mach_msg_type_number_t *new_stateCnt
 )
{
    /* unimplemented */
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity
(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t exception,
	mach_exception_data_t code,
	mach_msg_type_number_t codeCnt,
	int *flavor,
	thread_state_t old_state,
	mach_msg_type_number_t old_stateCnt,
	thread_state_t new_state,
	mach_msg_type_number_t *new_stateCnt
 )
{
    /* unimplemented */
    return KERN_FAILURE;
}