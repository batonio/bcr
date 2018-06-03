/* crypto/bn/bn_err.c */
/* ====================================================================
 * Copyright (c) 1999-2015 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

/*
 * NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_BN,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_BN,0,reason)

static ERR_STRING_DATA BN_str_functs[] = {
    {ERR_FUNC(BN_F_BNRAND), "BNRAND"},
    {ERR_FUNC(BN_F_BN_BLINDING_CONVERT_EX), "BN_BLINDING_convert_ex"},
    {ERR_FUNC(BN_F_BN_BLINDING_CREATE_PARAM), "BN_BLINDING_create_param"},
    {ERR_FUNC(BN_F_BN_BLINDING_INVERT_EX), "BN_BLINDING_invert_ex"},
    {ERR_FUNC(BN_F_BN_BLINDING_NEW), "BN_BLINDING_new"},
    {ERR_FUNC(BN_F_BN_BLINDING_UPDATE), "BN_BLINDING_update"},
    {ERR_FUNC(BN_F_BN_BN2DEC), "BN_bn2dec"},
    {ERR_FUNC(BN_F_BN_BN2HEX), "BN_bn2hex"},
    {ERR_FUNC(BN_F_BN_CTX_GET), "BN_CTX_get"},
    {ERR_FUNC(BN_F_BN_CTX_NEW), "BN_CTX_new"},
    {ERR_FUNC(BN_F_BN_CTX_START), "BN_CTX_start"},
    {ERR_FUNC(BN_F_BN_DIV), "BN_div"},
    {ERR_FUNC(BN_F_BN_DIV_NO_BRANCH), "BN_div_no_branch"},
    {ERR_FUNC(BN_F_BN_DIV_RECP), "BN_div_recp"},
    {ERR_FUNC(BN_F_BN_EXP), "BN_exp"},
    {ERR_FUNC(BN_F_BN_EXPAND2), "bn_expand2"},
    {ERR_FUNC(BN_F_BN_EXPAND_INTERNAL), "BN_EXPAND_INTERNAL"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD), "BN_GF2m_mod"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_EXP), "BN_GF2m_mod_exp"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_MUL), "BN_GF2m_mod_mul"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SOLVE_QUAD), "BN_GF2m_mod_solve_quad"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR), "BN_GF2m_mod_solve_quad_arr"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SQR), "BN_GF2m_mod_sqr"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SQRT), "BN_GF2m_mod_sqrt"},
    {ERR_FUNC(BN_F_BN_LSHIFT), "BN_lshift"},
    {ERR_FUNC(BN_F_BN_MOD_EXP2_MONT), "BN_mod_exp2_mont"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_MONT), "BN_mod_exp_mont"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_MONT_CONSTTIME), "BN_mod_exp_mont_consttime"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_MONT_WORD), "BN_mod_exp_mont_word"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_RECP), "BN_mod_exp_recp"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_SIMPLE), "BN_mod_exp_simple"},
    {ERR_FUNC(BN_F_BN_MOD_INVERSE), "BN_mod_inverse"},
    {ERR_FUNC(BN_F_BN_MOD_INVERSE_NO_BRANCH), "BN_mod_inverse_no_branch"},
    {ERR_FUNC(BN_F_BN_MOD_LSHIFT_QUICK), "BN_mod_lshift_quick"},
    {ERR_FUNC(BN_F_BN_MOD_MUL_RECIPROCAL), "BN_mod_mul_reciprocal"},
    {ERR_FUNC(BN_F_BN_MOD_SQRT), "BN_mod_sqrt"},
    {ERR_FUNC(BN_F_BN_MPI2BN), "BN_mpi2bn"},
    {ERR_FUNC(BN_F_BN_NEW), "BN_new"},
    {ERR_FUNC(BN_F_BN_RAND), "BN_rand"},
    {ERR_FUNC(BN_F_BN_RAND_RANGE), "BN_rand_range"},
    {ERR_FUNC(BN_F_BN_RSHIFT), "BN_rshift"},
    {ERR_FUNC(BN_F_BN_USUB), "BN_usub"},
    {0, NULL}
};

static ERR_STRING_DATA BN_str_reasons[] = {
    {ERR_REASON(BN_R_ARG2_LT_ARG3), "arg2 lt arg3"},
    {ERR_REASON(BN_R_BAD_RECIPROCAL), "bad reciprocal"},
    {ERR_REASON(BN_R_BIGNUM_TOO_LONG), "bignum too long"},
    {ERR_REASON(BN_R_BITS_TOO_SMALL), "bits too small"},
    {ERR_REASON(BN_R_CALLED_WITH_EVEN_MODULUS), "called with even modulus"},
    {ERR_REASON(BN_R_DIV_BY_ZERO), "div by zero"},
    {ERR_REASON(BN_R_ENCODING_ERROR), "encoding error"},
    {ERR_REASON(BN_R_EXPAND_ON_STATIC_BIGNUM_DATA),
     "expand on static bignum data"},
    {ERR_REASON(BN_R_INPUT_NOT_REDUCED), "input not reduced"},
    {ERR_REASON(BN_R_INVALID_LENGTH), "invalid length"},
    {ERR_REASON(BN_R_INVALID_RANGE), "invalid range"},
    {ERR_REASON(BN_R_INVALID_SHIFT), "invalid shift"},
    {ERR_REASON(BN_R_NOT_A_SQUARE), "not a square"},
    {ERR_REASON(BN_R_NOT_INITIALIZED), "not initialized"},
    {ERR_REASON(BN_R_NO_INVERSE), "no inverse"},
    {ERR_REASON(BN_R_NO_SOLUTION), "no solution"},
    {ERR_REASON(BN_R_P_IS_NOT_PRIME), "p is not prime"},
    {ERR_REASON(BN_R_TOO_MANY_ITERATIONS), "too many iterations"},
    {ERR_REASON(BN_R_TOO_MANY_TEMPORARY_VARIABLES),
     "too many temporary variables"},
    {0, NULL}
};

#endif

