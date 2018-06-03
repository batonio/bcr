/***********************************************************************
 *   File: main.cpp
 *   Author: Erofeev Alexander(erofeev_an@mail.ru)
 *   Date: 09.05.18
 ***********************************************************************/

#include <gosthash.h>
#include <gost_lcl.h>

#include "verify_gost_sign.h"

static void reversePubKey(
    const unsigned char *in, int inBufSize,
    unsigned char* out, const unsigned int outBufSize)
{
    for( int i = 0; i < outBufSize; ++i )
        out[i] = in[inBufSize-1-i];
}

static int pkey_gost01_cp_verify(EC_KEY* pub_key,
    const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbs_len)
{
    int ok = 0;
    DSA_SIG *s = unpack_cp_signature( sig, siglen );
    if (!s)
        return 0;

    if (pub_key)
        ok = gost2001_do_verify( tbs, tbs_len, s, pub_key );
    DSA_SIG_free(s);
    return ok;
}

int my_verify_gost(
    const unsigned char *in_hash,
    const byte *in_sign,
    char *in_pub1,
    char *in_pub2,
    int nid)
{
    int errcode = -1;
    EC_KEY *eckey = NULL;
    BIGNUM *X = NULL;
    BIGNUM *Y = NULL;
    EC_POINT *pub_key;
    Y = getbnfrombuf((const unsigned char*)in_pub1,32);
    X = getbnfrombuf((const unsigned char*)in_pub2,32);
    //Проверка ЭЦП
    if (!(eckey = EC_KEY_new())) {
        errcode = 1;
        goto err_exit;
    }
    if (!fill_GOST2001_params(eckey, nid)) {
        errcode = 2;
        goto err_exit;
    }
    if (!(pub_key = EC_POINT_new(EC_KEY_get0_group(eckey)))) {
        errcode = 3;
        goto err_exit;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(
            EC_KEY_get0_group(eckey),
            pub_key,
            X,
            Y,
            NULL)) {

        errcode = 4;
        goto err_exit;
    }
    if (!EC_KEY_set_public_key(eckey,pub_key)) {
        errcode = 5;
        goto err_exit;
    }
    if (!pkey_gost01_cp_verify(eckey, in_sign, 64, in_hash, 32)) {
        errcode = 6;
        goto err_exit;
    }
    else
        errcode = 0; //success

err_exit:
    if (pub_key) EC_POINT_free(pub_key);
    if (X) BN_free(X);
    if (Y) BN_free(Y);
    if (eckey) EC_KEY_free(eckey);
    return errcode;
}

void my_hash_gost(const byte *buf, int buflen, char *hash_res)
{
    gost_subst_block *b = &GostR3411_94_CryptoProParamSet;
    gost_hash_ctx ctx;
    init_gost_hash_ctx(&ctx,b);
    start_hash(&ctx);
    hash_block(&ctx,buf,buflen);
    finish_hash(&ctx,(byte *)hash_res);
}

int verify_gost_sign(
    unsigned char* data, unsigned int dataLength,
    unsigned char* signature,
    unsigned char* publicKey)
{
    unsigned char publicKeyReverse[64];
    reversePubKey( publicKey, 101, publicKeyReverse, sizeof(publicKeyReverse) );
    char hashGost[32];
    my_hash_gost( data, dataLength, hashGost );
    int err = my_verify_gost(
        (const unsigned char*)hashGost,
        signature,
        (char*)publicKeyReverse,
        (char*)publicKeyReverse + 32,
        NID_id_GostR3410_2001_CryptoPro_A_ParamSet);

    return err;
}
