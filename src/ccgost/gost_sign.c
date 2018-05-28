/**********************************************************************
 *                          gost_sign.c                               *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       Implementation of GOST R 34.10-94 signature algorithm        *
 *       for OpenSSL                                                  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "gost_params.h"
#include "gost_lcl.h"
#include "e_gost_err.h"

#ifdef DEBUG_SIGN
#else

# define dump_signature(a,b,c)
# define dump_dsa_sig(a,b)
#endif

/* Unpack signature according to cryptocom rules  */
/*-
DSA_SIG *unpack_cc_signature(const unsigned char *sig,size_t siglen)
        {
        DSA_SIG *s;
        s = DSA_SIG_new();
        if (s == NULL)
                {
                GOSTerr(GOST_F_UNPACK_CC_SIGNATURE,GOST_R_NO_MEMORY);
                return(NULL);
                }
        s->r = getbnfrombuf(sig, siglen/2);
        s->s = getbnfrombuf(sig + siglen/2, siglen/2);
        return s;
        }
*/
/* Unpack signature according to cryptopro rules  */
DSA_SIG *unpack_cp_signature(const unsigned char *sig, size_t siglen)
{
    DSA_SIG *s;

    s = DSA_SIG_new();
    if (s == NULL) {
        GOSTerr(GOST_F_UNPACK_CP_SIGNATURE, GOST_R_NO_MEMORY);
        return NULL;
    }
    s->s = getbnfrombuf(sig, siglen / 2);
    s->r = getbnfrombuf(sig + siglen / 2, siglen / 2);
    return s;
}

/* Convert little-endian byte array into bignum */
BIGNUM *hashsum2bn(const unsigned char *dgst)
{
    unsigned char buf[32];
    int i;
    for (i = 0; i < 32; i++) {
        buf[31 - i] = dgst[i];
    }
    return getbnfrombuf(buf, 32);
}

/* Convert byte buffer to bignum, skipping leading zeros*/
BIGNUM *getbnfrombuf(const unsigned char *buf, size_t len)
{
    while (*buf == 0 && len > 0) {
        buf++;
        len--;
    }
    if (len) {
        return BN_bin2bn(buf, len, NULL);
    } else {
        BIGNUM *b = BN_new();
        BN_zero(b);
        return b;
    }
}
