1. Файл с тестовыми парами ключей Owner и Active и файл с паролем от файла кошелька.
(файл кошелька по умолчанию ~/.local/share/eosio/nodeos/data/default.wallet)
2. Просмотр сертификата:
$ xca db.xdb
# После настройки согласно https://kirill-zak.ru/2015/08/13/298
$ openssl x509 -inform der -in CAMinfin.cer -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4e:3a:66:72:8d:8c:3e:9d:46:9f:94:e9:57:bc:62:47
    Signature Algorithm: GOST R 34.11-94 with GOST R 34.10-2001
        Issuer: 1.2.643.100.1=1037739085636/1.2.643.3.131.1.1=007710168360/street=\xD1\x83\xD0\xBB. \xD0\x98\xD0\xBB\xD1\x8C\xD0\xB8\xD0\xBD\xD0\xBA\xD0\xB0, \xD0\xB4. 9/emailAddress=ca@minfin.ru, C=RU, ST=\xD0\xB3. \xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, L=\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, O=\xD0\x9C\xD0\xB8\xD0\xBD\xD0\xB8\xD1\x81\xD1\x82\xD0\xB5\xD1\x80\xD1\x81\xD1\x82\xD0\xB2\xD0\xBE \xD1\x84\xD0\xB8\xD0\xBD\xD0\xB0\xD0\xBD\xD1\x81\xD0\xBE\xD0\xB2 \xD0\xA0\xD0\xBE\xD1\x81\xD1\x81\xD0\xB8\xD0\xB9\xD1\x81\xD0\xBA\xD0\xBE\xD0\xB9 \xD0\xA4\xD0\xB5\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8, CN=M\xD0\x98H\xD0\xA4\xD0\x98H Pocc\xD0\xB8\xD0\xB8
        Validity
            Not Before: Mar 23 08:11:11 2015 GMT
            Not After : Mar 23 08:11:11 2030 GMT
        Subject: 1.2.643.100.1=1037739085636/1.2.643.3.131.1.1=007710168360/street=\xD1\x83\xD0\xBB. \xD0\x98\xD0\xBB\xD1\x8C\xD0\xB8\xD0\xBD\xD0\xBA\xD0\xB0, \xD0\xB4. 9/emailAddress=ca@minfin.ru, C=RU, ST=\xD0\xB3. \xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, L=\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, O=\xD0\x9C\xD0\xB8\xD0\xBD\xD0\xB8\xD1\x81\xD1\x82\xD0\xB5\xD1\x80\xD1\x81\xD1\x82\xD0\xB2\xD0\xBE \xD1\x84\xD0\xB8\xD0\xBD\xD0\xB0\xD0\xBD\xD1\x81\xD0\xBE\xD0\xB2 \xD0\xA0\xD0\xBE\xD1\x81\xD1\x81\xD0\xB8\xD0\xB9\xD1\x81\xD0\xBA\xD0\xBE\xD0\xB9 \xD0\xA4\xD0\xB5\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8, CN=M\xD0\x98H\xD0\xA4\xD0\x98H Pocc\xD0\xB8\xD0\xB8
        Subject Public Key Info:
            Public Key Algorithm: GOST R 34.10-2001
                Public key:
                   X:B99ACD020027E2712870748AC91099803AB18FC3DB5ABAB89FCC47E8F981D7DC
                   Y:ECBD5E11A82EDD44DB0CAB855EE3261AE3E885F4795D06B7F74FE51FF57A3EF4
                Parameter set: id-GostR3410-2001-CryptoPro-A-ParamSet
        X509v3 extensions:
            1.2.643.100.111: 
                .m"....................-.................... .................................. ............ "............ HSM"
            1.2.643.100.112: 
                0..f.m"....................-.................... .................................. ............ "............ HSM".S"............................ .......... ".................. ...." ............ 1.5.O.................... ........................ ... ..../124-2274 .... 01.06.2013.O.................... ........................ ... ..../128-2130 .... 13.05.2013
            X509v3 Key Usage: 
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                B3:9F:D9:93:88:A1:85:00:64:1A:BE:98:CF:87:6E:65:39:DB:15:05
            1.3.6.1.4.1.311.21.1: 
                ...
            X509v3 Certificate Policies: 
                Policy: 1.2.643.100.113.1
                Policy: 1.2.643.100.113.2
                Policy: X509v3 Any Policy

    Signature Algorithm: GOST R 34.11-94 with GOST R 34.10-2001
         50:22:27:54:28:0e:ec:f6:67:8e:6a:3c:dc:26:e5:f1:9e:26:
         c8:ae:59:70:a7:ee:df:35:ab:1c:93:96:0c:42:b8:c7:4a:bd:
         e2:c0:b6:fa:82:01:60:8f:a9:71:5a:23:95:eb:9c:13:ab:12:
         dd:80:68:97:bf:b1:14:8e:1d:cf
$ openssl x509 -inform pem -in CAMinfin.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4e:3a:66:72:8d:8c:3e:9d:46:9f:94:e9:57:bc:62:47
    Signature Algorithm: GOST R 34.11-94 with GOST R 34.10-2001
        Issuer: 1.2.643.100.1=1037739085636/1.2.643.3.131.1.1=007710168360/street=\xD1\x83\xD0\xBB. \xD0\x98\xD0\xBB\xD1\x8C\xD0\xB8\xD0\xBD\xD0\xBA\xD0\xB0, \xD0\xB4. 9/emailAddress=ca@minfin.ru, C=RU, ST=\xD0\xB3. \xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, L=\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, O=\xD0\x9C\xD0\xB8\xD0\xBD\xD0\xB8\xD1\x81\xD1\x82\xD0\xB5\xD1\x80\xD1\x81\xD1\x82\xD0\xB2\xD0\xBE \xD1\x84\xD0\xB8\xD0\xBD\xD0\xB0\xD0\xBD\xD1\x81\xD0\xBE\xD0\xB2 \xD0\xA0\xD0\xBE\xD1\x81\xD1\x81\xD0\xB8\xD0\xB9\xD1\x81\xD0\xBA\xD0\xBE\xD0\xB9 \xD0\xA4\xD0\xB5\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8, CN=M\xD0\x98H\xD0\xA4\xD0\x98H Pocc\xD0\xB8\xD0\xB8
        Validity
            Not Before: Mar 23 08:11:11 2015 GMT
            Not After : Mar 23 08:11:11 2030 GMT
        Subject: 1.2.643.100.1=1037739085636/1.2.643.3.131.1.1=007710168360/street=\xD1\x83\xD0\xBB. \xD0\x98\xD0\xBB\xD1\x8C\xD0\xB8\xD0\xBD\xD0\xBA\xD0\xB0, \xD0\xB4. 9/emailAddress=ca@minfin.ru, C=RU, ST=\xD0\xB3. \xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, L=\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0, O=\xD0\x9C\xD0\xB8\xD0\xBD\xD0\xB8\xD1\x81\xD1\x82\xD0\xB5\xD1\x80\xD1\x81\xD1\x82\xD0\xB2\xD0\xBE \xD1\x84\xD0\xB8\xD0\xBD\xD0\xB0\xD0\xBD\xD1\x81\xD0\xBE\xD0\xB2 \xD0\xA0\xD0\xBE\xD1\x81\xD1\x81\xD0\xB8\xD0\xB9\xD1\x81\xD0\xBA\xD0\xBE\xD0\xB9 \xD0\xA4\xD0\xB5\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8, CN=M\xD0\x98H\xD0\xA4\xD0\x98H Pocc\xD0\xB8\xD0\xB8
        Subject Public Key Info:
            Public Key Algorithm: GOST R 34.10-2001
                Public key:
                   X:B99ACD020027E2712870748AC91099803AB18FC3DB5ABAB89FCC47E8F981D7DC
                   Y:ECBD5E11A82EDD44DB0CAB855EE3261AE3E885F4795D06B7F74FE51FF57A3EF4
                Parameter set: id-GostR3410-2001-CryptoPro-A-ParamSet
        X509v3 extensions:
            1.2.643.100.111: 
                .m"....................-.................... .................................. ............ "............ HSM"
            1.2.643.100.112: 
                0..f.m"....................-.................... .................................. ............ "............ HSM".S"............................ .......... ".................. ...." ............ 1.5.O.................... ........................ ... ..../124-2274 .... 01.06.2013.O.................... ........................ ... ..../128-2130 .... 13.05.2013
            X509v3 Key Usage: 
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                B3:9F:D9:93:88:A1:85:00:64:1A:BE:98:CF:87:6E:65:39:DB:15:05
            1.3.6.1.4.1.311.21.1: 
                ...
            X509v3 Certificate Policies: 
                Policy: 1.2.643.100.113.1
                Policy: 1.2.643.100.113.2
                Policy: X509v3 Any Policy

    Signature Algorithm: GOST R 34.11-94 with GOST R 34.10-2001
         50:22:27:54:28:0e:ec:f6:67:8e:6a:3c:dc:26:e5:f1:9e:26:
         c8:ae:59:70:a7:ee:df:35:ab:1c:93:96:0c:42:b8:c7:4a:bd:
         e2:c0:b6:fa:82:01:60:8f:a9:71:5a:23:95:eb:9c:13:ab:12:
         dd:80:68:97:bf:b1:14:8e:1d:cf
