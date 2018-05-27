/***********************************************************************
 *   File: main.cpp
 *   Author: Erofeev Alexander(erofeev_an@mail.ru)
 *   Date: 09.05.18
 ***********************************************************************/
#include <iostream>

extern "C" {
#include <gosthash.h>
#include <gost_lcl.h>
}

//101 - оригинальный публичный ключ
unsigned char pub_key[] = {
    0x30, 0x63, 0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13,
    0x30, 0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x06,
    0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01, 0x03, 0x43, 0x00, 0x04,
    0x40, 0x30, 0x6f, 0x58, 0xd9, 0x32, 0xa2, 0x2e, 0x90, 0x1f, 0x18, 0x04,
    0x39, 0x0c, 0xdb, 0x95, 0x4d, 0x73, 0xaf, 0x6c, 0x3f, 0x40, 0xf9, 0x8e,
    0x22, 0xfa, 0xb7, 0xc2, 0xf9, 0xa2, 0x30, 0xe7, 0x12, 0x9f, 0x53, 0x8d,
    0x07, 0x2b, 0x39, 0x84, 0xd0, 0x4d, 0x63, 0x29, 0x7e, 0x4e, 0xe7, 0x5c,
    0xc3, 0x1d, 0xc2, 0x9f, 0x62, 0xaa, 0x73, 0xbe, 0xe5, 0x12, 0x2b, 0x4f,
    0xde, 0xa0, 0x2c, 0xd8, 0xc5
};
//64 - перевёрнутый публичный ключ + только 64 байта вместо 101
unsigned char pub_key_rev[] = {
    0xc5, 0xd8, 0x2c, 0xa0, 0xde, 0x4f, 0x2b, 0x12, 0xe5, 0xbe, 0x73, 0xaa,
    0x62, 0x9f, 0xc2, 0x1d, 0xc3, 0x5c, 0xe7, 0x4e, 0x7e, 0x29, 0x63, 0x4d,
    0xd0, 0x84, 0x39, 0x2b, 0x07, 0x8d, 0x53, 0x9f, 0x12, 0xe7, 0x30, 0xa2,
    0xf9, 0xc2, 0xb7, 0xfa, 0x22, 0x8e, 0xf9, 0x40, 0x3f, 0x6c, 0xaf, 0x73,
    0x4d, 0x95, 0xdb, 0x0c, 0x39, 0x04, 0x18, 0x1f, 0x90, 0x2e, 0xa2, 0x32,
    0xd9, 0x58, 0x6f, 0x30
};
//Строка "EOS8kVQYVCyjqG99FGygjFXYTW2rUNEz9toq9dNR79TUYpCGehpXF\n";
//unsigned char data_txt[] = "EOS8kVQYVCyjqG99FGygjFXYTW2rUNEz9toq9dNR79TUYpCGehpXF\n";
unsigned char data_txt[] = {
    0x45, 0x4f, 0x53, 0x38, 0x6b, 0x56, 0x51, 0x59, 0x56, 0x43, 0x79, 0x6a,
    0x71, 0x47, 0x39, 0x39, 0x46, 0x47, 0x79, 0x67, 0x6a, 0x46, 0x58, 0x59,
    0x54, 0x57, 0x32, 0x72, 0x55, 0x4e, 0x45, 0x7a, 0x39, 0x74, 0x6f, 0x71,
    0x39, 0x64, 0x4e, 0x52, 0x37, 0x39, 0x54, 0x55, 0x59, 0x70, 0x43, 0x47,
    0x65, 0x68, 0x70, 0x58, 0x46, 0x0a
};

//64
const unsigned char data_txt_sig[] = {
    0xcc, 0x4d, 0xf5, 0x3b, 0xf7, 0xbd, 0x34, 0x07, 0x8e, 0x81, 0xab, 0xc5,
    0xcc, 0x46, 0xea, 0x7b, 0xc7, 0xe2, 0x57, 0x9b, 0xad, 0xa8, 0x58, 0x7b,
    0x22, 0xb7, 0xe6, 0xfc, 0xd9, 0x3d, 0x6b, 0x35, 0xb9, 0xac, 0x7c, 0x98,
    0xde, 0x43, 0x07, 0xb1, 0x96, 0xa3, 0x23, 0xda, 0xfb, 0x25, 0x64, 0x31,
    0xdc, 0x41, 0xbb, 0xe1, 0x8f, 0x2c, 0x42, 0x8d, 0xc5, 0x11, 0xcc, 0x1d,
    0x6a, 0x0b, 0xa5, 0x89
};


//Глобальные переменные для хеша и публичного ключа
char hash_gost[32];
char public_key[64];

static int pkey_gost01_cp_verify(EC_KEY* pub_key,
    const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbs_len)
{
    int ok = 0;
//    std::cerr<<sig;
    std::cerr<<"### Before unpack_cp_signature\n";
    DSA_SIG *s = unpack_cp_signature( sig, siglen );
    if (!s)
        return 0;

    std::cerr<<"### gost2001_do_verify\n";
    if (pub_key)
        ok = gost2001_do_verify( tbs, tbs_len, s, pub_key );
    DSA_SIG_free(s);
    return ok;
}

int my_verify_gost(
    const unsigned char *in_hash, const byte *in_sign, char *in_pub1, char *in_pub2, int nid)
{
    int errcode;
    EC_KEY *eckey = NULL;
    BIGNUM *X = NULL;
    BIGNUM *Y = NULL;
    EC_POINT *pub_key;
    std::cerr<<"### Before getbnfrombuf for Y\n";
    Y = getbnfrombuf((const unsigned char*)in_pub1,32);
    std::cerr<<"### Before getbnfrombuf for X\n";
    X = getbnfrombuf((const unsigned char*)in_pub2,32);
    std::cerr<<"### Before EC_KEY_new\n";
    //Проверка ЭЦП
    if (!(eckey = EC_KEY_new())) {
        errcode = 1;
        goto err_exit;
    }
    std::cerr<<"### Before fill_GOST2001_params\n";
    if (!fill_GOST2001_params(eckey, nid)) {
        errcode = 2;
        goto err_exit;
    }
    std::cerr<<"### Before EC_POINT_new\n";
    if (!(pub_key = EC_POINT_new(EC_KEY_get0_group(eckey)))) {
        errcode = 3;
        goto err_exit;
    }
    std::cerr<<"### Before  EC_POINT_set_affine_coordinates_GFp\n";
    if (!EC_POINT_set_affine_coordinates_GFp(
            EC_KEY_get0_group(eckey),
            pub_key,
            X,
            Y,
            NULL)) {

        errcode = 4;
        goto err_exit;
    }
    std::cerr<<"### Before EC_KEY_set_public_key\n";
    if (!EC_KEY_set_public_key(eckey,pub_key)) {
        errcode = 5;
        goto err_exit;
    }
    std::cerr<<"### Before pkey_gost01_cp_verify\n";
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

int main() {
    std::cerr<<"### Before hashing\n";
    my_hash_gost( data_txt, sizeof(data_txt), hash_gost );
    std::cerr<<"### Before verifying\n";
    int err = my_verify_gost(
        (const unsigned char*)hash_gost,
        data_txt_sig,
        (char*)pub_key_rev,
        (char*)pub_key_rev + 32,
        NID_id_GostR3410_2001_CryptoPro_A_ParamSet);

    std::cout<<err<<std::endl;
    return err;
}
