/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * OpenHarmony Common Kernel Vendor Hook Support
 * Based on include/trace/hooks/lite_vendor_hooks.h
 *
 */

#ifndef LITE_VENDOR_HOOK_H
#define LITE_VENDOR_HOOK_H

#include <asm/bug.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/tracepoint.h>
#include <linux/module.h>

struct __lvh_func {
        void *func;
        void *data;
        bool has_data;
};

struct lite_vendor_hook {
        struct mutex mutex;
        struct __lvh_func *funcs;
};
#endif // LITE_VENDOR_HOOK_H

#ifdef CREATE_LITE_VENDOR_HOOK

#define DEFINE_HCK_LITE_HOOK(name, proto, args) \
        struct lite_vendor_hook __lvh_##name __used     \
        __section("__vendor_hooks") = { \
                .mutex = __MUTEX_INITIALIZER(__lvh_##name.mutex),       \
                .funcs = NULL };        \
        EXPORT_SYMBOL(__lvh_##name);    \
        void lvh_probe_##name(proto) { return; }        \
        void lvh_probe_data_##name(void *lvh_data, proto) { return; }

#undef DECLARE_HCK_LITE_HOOK
#define DECLARE_HCK_LITE_HOOK(name, proto, args)        \
        DEFINE_HCK_LITE_HOOK(name, PARAMS(proto), PARAMS(args))

#else // #ifndef CREATE_LITE_VENDOR_HOOK

#define REGISTER_HCK_LITE_HOOK(name, probe)     \
        extern typeof(lvh_probe_##name) (probe);  \
        do {    \
                if (register_lvh_##name(probe)) \
                        WARN_ONCE(1, "LVH register failed!\n"); \
        } while (0)

#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)  \
        extern typeof(lvh_probe_data_##name) (probe);     \
        do {    \
                if (register_lvh_data_##name(probe, data))      \
                        WARN_ONCE(1, "LVH register failed!\n"); \
        } while (0)

#define CALL_HCK_LITE_HOOK(name, args...)       \
        call_lvh_##name(args)

#define __DECLARE_HCK_LITE_HOOK(name, proto, args)      \
        extern struct lite_vendor_hook __lvh_##name;    \
        extern void lvh_probe_##name(proto);    \
        extern void lvh_probe_data_##name(void *lvh_data, proto);       \
        static inline void      \
        call_lvh_##name(proto)  \
        {       \
                struct __lvh_func *funcs = (&__lvh_##name)->funcs;      \
                if (funcs && funcs->func) {     \
                        if (funcs->has_data)    \
                                ((void(*)(void *, proto))funcs->func)(funcs->data, args);       \
                        else    \
                                ((void(*)(proto))funcs->func)(args);    \
                }       \
        }       \
        static inline int       \
        __register_lvh_##name(void *probe, void *data, bool has_data)   \
        {       \
                int err = 0;    \
                struct __lvh_func *funcs;       \
                struct module *mod;     \
                mutex_lock(&__lvh_##name.mutex);        \
                funcs = (&__lvh_##name)->funcs; \
                if (funcs) {    \
                        if (funcs->func != probe || funcs->data != data)        \
                                err = -EBUSY;   \
                        goto out;       \
                }       \
                \
                funcs = (struct __lvh_func*)kmalloc(sizeof(struct __lvh_func), GFP_KERNEL);     \
                if (!funcs) {   \
                        err = -ENOMEM;  \
                        goto out;       \
                }       \
                \
                funcs->func = probe;    \
                funcs->data = data;     \
                funcs->has_data = has_data;     \
                mod = __module_address((uintptr_t)probe);       \
                if (mod)        \
                        (void)try_module_get(mod);      \
                (&__lvh_##name)->funcs = funcs; \
        out:    \
                mutex_unlock(&__lvh_##name.mutex);      \
                return err;     \
        }       \
        static inline int       \
        register_lvh_##name(void (*probe)(proto))       \
        {       \
                return __register_lvh_##name((void *)probe, NULL, false);       \
        }       \
        static inline int       \
        register_lvh_data_##name(void (*probe)(void *lvh_data, proto), void *data)      \
        {       \
                return __register_lvh_##name((void *)probe, data, true);        \
        }

#undef DECLARE_HCK_LITE_HOOK
#define DECLARE_HCK_LITE_HOOK(name, proto, args)        \
        __DECLARE_HCK_LITE_HOOK(name, PARAMS(proto), PARAMS(args))

#endif // CREATE_LITE_VENDOR_HOOK
