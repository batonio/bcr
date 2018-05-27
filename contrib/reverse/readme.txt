1. Создать сертификат, аналогичный по алгоритмам шифрования с CAMinfin.cer
openssl req -days 3650 -x509 -newkey gost2001 -pkeyopt paramset:A -nodes -keyout gost_test.key -out gost_test.crt

2. Подписать файл приватным ключом
openssl dgst -md_gost94 -sign gost_test.key -keyform PEM -out data.txt.sig data.txt

3. Проверить подпись при помощи публичного ключа
cat data.txt | openssl dgst -engine gost -md_gost94 -verify <(openssl x509 -engine gost -in gost_test.crt -pubkey -noout) -signature data.txt.sig
openssl dgst -engine gost -md_gost94 -verify <(openssl x509 -engine gost -in gost_test.crt -pubkey -noout) -signature data.txt.sig data.txt
openssl dgst -engine gost -md_gost94 -verify pub.key -signature data.txt.sig data.txt

Verified OK

4. Проверить что проверка другого файла фэйлится
cat data.txt | openssl dgst -engine gost -md_gost94 -verify <(openssl x509 -engine gost -in gost_test.crt -pubkey -noout) -signature readme.txt
openssl dgst -engine gost -md_gost94 -verify <(openssl x509 -engine gost -in gost_test.crt -pubkey -noout) -signature readme.txt data.txt
openssl dgst -engine gost -md_gost94 -verify pub.key -signature readme.txt data.txt


Verification Failure
