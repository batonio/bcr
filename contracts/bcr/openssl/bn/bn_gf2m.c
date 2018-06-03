/* crypto/bn/bn_gf2m.c */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the ECC Code as delivered hereunder (or portions thereof),
 * provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the ECC Code;
 *  2) separates from the ECC Code; or
 *  3) for infringements caused by:
 *       i) the modification of the ECC Code or
 *      ii) the combination of the ECC Code with other software or
 *          devices where such combination causes the infringement.
 *
 * The software is originally written by Sheueling Chang Shantz and
 * Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

/*
 * NOTE: This file is licensed pursuant to the OpenSSL license below and may
 * be modified; but after modifications, the above covenant may no longer
 * apply! In such cases, the corresponding paragraph ["In addition, Sun
 * covenants ... causes the infringement."] and this note can be edited out;
 * but please keep the Sun copyright notice and attribution.
 */

/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"

#ifndef OPENSSL_NO_EC2M

/*
 * Maximum number of iterations before BN_GF2m_mod_solve_quad_arr should
 * fail.
 */
# define MAX_ITERATIONS 50

static const BN_ULONG SQR_tb[16] = { 0, 1, 4, 5, 16, 17, 20, 21,
    64, 65, 68, 69, 80, 81, 84, 85
};

/* Platform-specific macros to accelerate squaring. */
# if defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
#  define SQR1(w) \
    SQR_tb[(w) >> 60 & 0xF] << 56 | SQR_tb[(w) >> 56 & 0xF] << 48 | \
    SQR_tb[(w) >> 52 & 0xF] << 40 | SQR_tb[(w) >> 48 & 0xF] << 32 | \
    SQR_tb[(w) >> 44 & 0xF] << 24 | SQR_tb[(w) >> 40 & 0xF] << 16 | \
    SQR_tb[(w) >> 36 & 0xF] <<  8 | SQR_tb[(w) >> 32 & 0xF]
#  define SQR0(w) \
    SQR_tb[(w) >> 28 & 0xF] << 56 | SQR_tb[(w) >> 24 & 0xF] << 48 | \
    SQR_tb[(w) >> 20 & 0xF] << 40 | SQR_tb[(w) >> 16 & 0xF] << 32 | \
    SQR_tb[(w) >> 12 & 0xF] << 24 | SQR_tb[(w) >>  8 & 0xF] << 16 | \
    SQR_tb[(w) >>  4 & 0xF] <<  8 | SQR_tb[(w)       & 0xF]
# endif
# ifdef THIRTY_TWO_BIT
#  define SQR1(w) \
    SQR_tb[(w) >> 28 & 0xF] << 24 | SQR_tb[(w) >> 24 & 0xF] << 16 | \
    SQR_tb[(w) >> 20 & 0xF] <<  8 | SQR_tb[(w) >> 16 & 0xF]
#  define SQR0(w) \
    SQR_tb[(w) >> 12 & 0xF] << 24 | SQR_tb[(w) >>  8 & 0xF] << 16 | \
    SQR_tb[(w) >>  4 & 0xF] <<  8 | SQR_tb[(w)       & 0xF]
# endif

# if !defined(OPENSSL_BN_ASM_GF2m)
/*
 * Product of two polynomials a, b each with degree < BN_BITS2 - 1, result is
 * a polynomial r with degree < 2 * BN_BITS - 1 The caller MUST ensure that
 * the variables have the right amount of space allocated.
 */
#  ifdef THIRTY_TWO_BIT
static void bn_GF2m_mul_1x1(BN_ULONG *r1, BN_ULONG *r0, const BN_ULONG a,
                            const BN_ULONG b)
{
    register BN_ULONG h, l, s;
    BN_ULONG tab[8], top2b = a >> 30;
    register BN_ULONG a1, a2, a4;

    a1 = a & (0x3FFFFFFF);
    a2 = a1 << 1;
    a4 = a2 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = a1 ^ a2 ^ a4;

    s = tab[b & 0x7];
    l = s;
    s = tab[b >> 3 & 0x7];
    l ^= s << 3;
    h = s >> 29;
    s = tab[b >> 6 & 0x7];
    l ^= s << 6;
    h ^= s >> 26;
    s = tab[b >> 9 & 0x7];
    l ^= s << 9;
    h ^= s >> 23;
    s = tab[b >> 12 & 0x7];
    l ^= s << 12;
    h ^= s >> 20;
    s = tab[b >> 15 & 0x7];
    l ^= s << 15;
    h ^= s >> 17;
    s = tab[b >> 18 & 0x7];
    l ^= s << 18;
    h ^= s >> 14;
    s = tab[b >> 21 & 0x7];
    l ^= s << 21;
    h ^= s >> 11;
    s = tab[b >> 24 & 0x7];
    l ^= s << 24;
    h ^= s >> 8;
    s = tab[b >> 27 & 0x7];
    l ^= s << 27;
    h ^= s >> 5;
    s = tab[b >> 30];
    l ^= s << 30;
    h ^= s >> 2;

    /* compensate for the top two bits of a */

    if (top2b & 01) {
        l ^= b << 30;
        h ^= b >> 2;
    }
    if (top2b & 02) {
        l ^= b << 31;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}
#  endif
#  if defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
#  endif

# else
void bn_GF2m_mul_2x2(BN_ULONG *r, BN_ULONG a1, BN_ULONG a0, BN_ULONG b1,
                     BN_ULONG b0);
# endif

# ifndef OPENSSL_SUN_GF2M_DIV
# else
/*
 * Divide y by x, reduce modulo p, and store the result in r. r could be x
 * or y, x could equal y. Uses algorithm Modular_Division_GF(2^m) from
 * Chang-Shantz, S.  "From Euclid's GCD to Montgomery Multiplication to the
 * Great Divide".
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x,
                    const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *a, *b, *u, *v;
    int ret = 0;

    bn_check_top(y);
    bn_check_top(x);
    bn_check_top(p);

    BN_CTX_start(ctx);

    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    u = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);
    if (v == NULL)
        goto err;

    /* reduce x and y mod p */
    if (!BN_GF2m_mod(u, y, p))
        goto err;
    if (!BN_GF2m_mod(a, x, p))
        goto err;
    if (!BN_copy(b, p))
        goto err;

    while (!BN_is_odd(a)) {
        if (!BN_rshift1(a, a))
            goto err;
        if (BN_is_odd(u))
            if (!BN_GF2m_add(u, u, p))
                goto err;
        if (!BN_rshift1(u, u))
            goto err;
    }

    do {
        if (BN_GF2m_cmp(b, a) > 0) {
            if (!BN_GF2m_add(b, b, a))
                goto err;
            if (!BN_GF2m_add(v, v, u))
                goto err;
            do {
                if (!BN_rshift1(b, b))
                    goto err;
                if (BN_is_odd(v))
                    if (!BN_GF2m_add(v, v, p))
                        goto err;
                if (!BN_rshift1(v, v))
                    goto err;
            } while (!BN_is_odd(b));
        } else if (BN_abs_is_word(a, 1))
            break;
        else {
            if (!BN_GF2m_add(a, a, b))
                goto err;
            if (!BN_GF2m_add(u, u, v))
                goto err;
            do {
                if (!BN_rshift1(a, a))
                    goto err;
                if (BN_is_odd(u))
                    if (!BN_GF2m_add(u, u, p))
                        goto err;
                if (!BN_rshift1(u, u))
                    goto err;
            } while (!BN_is_odd(a));
        }
    } while (1);

    if (!BN_copy(r, u))
        goto err;
    bn_check_top(r);
    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}
# endif
#endif
