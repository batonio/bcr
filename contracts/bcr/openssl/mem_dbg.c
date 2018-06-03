/* crypto/mem_dbg.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/lhash.h>

static int mh_mode = CRYPTO_MEM_CHECK_OFF;
/*
 * The state changes to CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE when
 * the application asks for it (usually after library initialisation for
 * which no book-keeping is desired). State CRYPTO_MEM_CHECK_ON exists only
 * temporarily when the library thinks that certain allocations should not be
 * checked (e.g. the data structures used for memory checking).  It is not
 * suitable as an initial state: the library will unexpectedly enable memory
 * checking when it executes one of those sections that want to disable
 * checking temporarily. State CRYPTO_MEM_CHECK_ENABLE without ..._ON makes
 * no sense whatsoever.
 */

static unsigned long order = 0; /* number of memory requests */

DECLARE_LHASH_OF(MEM);
static LHASH_OF(MEM) *mh = NULL; /* hash-table of memory requests (address as
                                  * key); access requires MALLOC2 lock */

typedef struct app_mem_info_st
/*-
 * For application-defined information (static C-string `info')
 * to be displayed in memory leak list.
 * Each thread has its own stack.  For applications, there is
 *   CRYPTO_push_info("...")     to push an entry,
 *   CRYPTO_pop_info()           to pop an entry,
 *   CRYPTO_remove_all_info()    to pop all entries.
 */
{
    CRYPTO_THREADID threadid;
    const char *file;
    int line;
    const char *info;
    struct app_mem_info_st *next; /* tail of thread's stack */
    int references;
} APP_INFO;

static void app_info_free(APP_INFO *);

DECLARE_LHASH_OF(APP_INFO);
static LHASH_OF(APP_INFO) *amih = NULL; /* hash-table with those
                                         * app_mem_info_st's that are at the
                                         * top of their thread's stack (with
                                         * `thread' as key); access requires
                                         * MALLOC2 lock */

typedef struct mem_st
/* memory-block description */
{
    void *addr;
    int num;
    const char *file;
    int line;
    CRYPTO_THREADID threadid;
    unsigned long order;
    time_t time;
    APP_INFO *app_info;
} MEM;

static long options =           /* extra information to be recorded */
#if defined(CRYPTO_MDEBUG_TIME) || defined(CRYPTO_MDEBUG_ALL)
    V_CRYPTO_MDEBUG_TIME |
#endif
#if defined(CRYPTO_MDEBUG_THREAD) || defined(CRYPTO_MDEBUG_ALL)
    V_CRYPTO_MDEBUG_THREAD |
#endif
    0;

static unsigned int num_disable = 0; /* num_disable > 0 iff mh_mode ==
                                      * CRYPTO_MEM_CHECK_ON (w/o ..._ENABLE) */

/*
 * Valid iff num_disable > 0.  CRYPTO_LOCK_MALLOC2 is locked exactly in this
 * case (by the thread named in disabling_thread).
 */
static CRYPTO_THREADID disabling_threadid;

static void app_info_free(APP_INFO *inf)
{
    if (--(inf->references) <= 0) {
        if (inf->next != NULL) {
            app_info_free(inf->next);
        }
        OPENSSL_free(inf);
    }
}

int CRYPTO_mem_ctrl(int mode)
{
    int ret = mh_mode;

    CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
    switch (mode) {
        /*
         * for applications (not to be called while multiple threads use the
         * library):
         */
    case CRYPTO_MEM_CHECK_ON:  /* aka MemCheck_start() */
        mh_mode = CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE;
        num_disable = 0;
        break;
    case CRYPTO_MEM_CHECK_OFF: /* aka MemCheck_stop() */
        mh_mode = 0;
        num_disable = 0;        /* should be true *before* MemCheck_stop is
                                 * used, or there'll be a lot of confusion */
        break;

        /* switch off temporarily (for library-internal use): */
    case CRYPTO_MEM_CHECK_DISABLE: /* aka MemCheck_off() */
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            CRYPTO_THREADID cur;
            CRYPTO_THREADID_current(&cur);
            /* see if we don't have the MALLOC2 lock already */
            if (!num_disable
                || CRYPTO_THREADID_cmp(&disabling_threadid, &cur)) {
                /*
                 * Long-time lock CRYPTO_LOCK_MALLOC2 must not be claimed
                 * while we're holding CRYPTO_LOCK_MALLOC, or we'll deadlock
                 * if somebody else holds CRYPTO_LOCK_MALLOC2 (and cannot
                 * release it because we block entry to this function). Give
                 * them a chance, first, and then claim the locks in
                 * appropriate order (long-time lock first).
                 */
                CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
                /*
                 * Note that after we have waited for CRYPTO_LOCK_MALLOC2 and
                 * CRYPTO_LOCK_MALLOC, we'll still be in the right "case" and
                 * "if" branch because MemCheck_start and MemCheck_stop may
                 * never be used while there are multiple OpenSSL threads.
                 */
                CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
                CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
                mh_mode &= ~CRYPTO_MEM_CHECK_ENABLE;
                CRYPTO_THREADID_cpy(&disabling_threadid, &cur);
            }
            num_disable++;
        }
        break;
    case CRYPTO_MEM_CHECK_ENABLE: /* aka MemCheck_on() */
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            if (num_disable) {  /* always true, or something is going wrong */
                num_disable--;
                if (num_disable == 0) {
                    mh_mode |= CRYPTO_MEM_CHECK_ENABLE;
                    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
                }
            }
        }
        break;

    default:
        break;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
    return (ret);
}

int CRYPTO_is_mem_check_on(void)
{
    int ret = 0;

    if (mh_mode & CRYPTO_MEM_CHECK_ON) {
        CRYPTO_THREADID cur;
        CRYPTO_THREADID_current(&cur);
        CRYPTO_r_lock(CRYPTO_LOCK_MALLOC);

        ret = (mh_mode & CRYPTO_MEM_CHECK_ENABLE)
            || CRYPTO_THREADID_cmp(&disabling_threadid, &cur);

        CRYPTO_r_unlock(CRYPTO_LOCK_MALLOC);
    }
    return (ret);
}

/* static int app_info_cmp(APP_INFO *a, APP_INFO *b) */

static int app_info_cmp(const void *a_void, const void *b_void)
{
    return CRYPTO_THREADID_cmp(&((const APP_INFO *)a_void)->threadid,
                               &((const APP_INFO *)b_void)->threadid);
}

static IMPLEMENT_LHASH_COMP_FN(app_info, APP_INFO)

static unsigned long app_info_hash(const APP_INFO *a)
{
    unsigned long ret;

    ret = CRYPTO_THREADID_hash(&a->threadid);
    /* This is left in as a "who am I to question legacy?" measure */
    ret = ret * 17851 + (ret >> 14) * 7 + (ret >> 4) * 251;
    return (ret);
}

static IMPLEMENT_LHASH_HASH_FN(app_info, APP_INFO)

static APP_INFO *pop_info(void)
{
    APP_INFO tmp;
    APP_INFO *ret = NULL;

    if (amih != NULL) {
        CRYPTO_THREADID_current(&tmp.threadid);
        if ((ret = lh_APP_INFO_delete(amih, &tmp)) != NULL) {
            APP_INFO *next = ret->next;

            if (next != NULL) {
                next->references++;
                (void)lh_APP_INFO_insert(amih, next);
            }
#ifdef LEVITTE_DEBUG_MEM
            if (CRYPTO_THREADID_cmp(&ret->threadid, &tmp.threadid)) {
                fprintf(stderr,
                        "pop_info(): deleted info has other thread ID (%lu) than the current thread (%lu)!!!!\n",
                        CRYPTO_THREADID_hash(&ret->threadid),
                        CRYPTO_THREADID_hash(&tmp.threadid));
                abort();
            }
#endif
            if (--(ret->references) <= 0) {
                ret->next = NULL;
                if (next != NULL)
                    next->references--;
                OPENSSL_free(ret);
            }
        }
    }
    return (ret);
}

int CRYPTO_push_info_(const char *info, const char *file, int line)
{
    APP_INFO *ami, *amim;
    int ret = 0;

    if (is_MemCheck_on()) {
        MemCheck_off();         /* obtain MALLOC2 lock */

        if ((ami = (APP_INFO *)OPENSSL_malloc(sizeof(APP_INFO))) == NULL) {
            ret = 0;
            goto err;
        }
        if (amih == NULL) {
            if ((amih = lh_APP_INFO_new()) == NULL) {
                OPENSSL_free(ami);
                ret = 0;
                goto err;
            }
        }

        CRYPTO_THREADID_current(&ami->threadid);
        ami->file = file;
        ami->line = line;
        ami->info = info;
        ami->references = 1;
        ami->next = NULL;

        if ((amim = lh_APP_INFO_insert(amih, ami)) != NULL) {
#ifdef LEVITTE_DEBUG_MEM
            if (CRYPTO_THREADID_cmp(&ami->threadid, &amim->threadid)) {
                fprintf(stderr,
                        "CRYPTO_push_info(): previous info has other thread ID (%lu) than the current thread (%lu)!!!!\n",
                        CRYPTO_THREADID_hash(&amim->threadid),
                        CRYPTO_THREADID_hash(&ami->threadid));
                abort();
            }
#endif
            ami->next = amim;
        }
 err:
        MemCheck_on();          /* release MALLOC2 lock */
    }

    return (ret);
}

int CRYPTO_pop_info(void)
{
    int ret = 0;

    if (is_MemCheck_on()) {     /* _must_ be true, or something went severely
                                 * wrong */
        MemCheck_off();         /* obtain MALLOC2 lock */

        ret = (pop_info() != NULL);

        MemCheck_on();          /* release MALLOC2 lock */
    }
    return (ret);
}
