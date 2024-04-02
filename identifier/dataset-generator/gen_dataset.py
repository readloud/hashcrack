import base64
import codecs
import concurrent.futures
from Crypto.Hash import HMAC, keccak, SHA1, SHA256, SHA512
import csv
import fastcrc
import hashlib
import os
from passlib.hash import (
    apr_md5_crypt, argon2, atlassian_pbkdf2_sha1, bcrypt, bsdi_crypt, cisco_asa, cisco_pix, cisco_type7, des_crypt,
    django_argon2, django_bcrypt, django_bcrypt_sha256, django_des_crypt, django_pbkdf2_sha1, django_pbkdf2_sha256,
    django_salted_md5, django_salted_sha1, grub_pbkdf2_sha512,
    ldap_md5, ldap_salted_md5, ldap_salted_sha1, ldap_salted_sha256, ldap_salted_sha512, ldap_sha1,
    lmhash, md5_crypt, mssql2000, mssql2005, mysql323, mysql41, oracle10, oracle11, phpass,
    postgres_md5, scram, scrypt, sha1_crypt, sha256_crypt, sha512_crypt)
import re
import time


dataset_path = os.path.dirname(__file__) + "/../dataset/"

header = [
    'type',
    'encoded_text',
    'scheme',
    'num_of_chars',
    'contains_bit_only',
    'contains_decimal_only',
    'contains_hex_only',
    'contains_alpha_only',
    'contains_upper_case_only',
    'contains_lower_case_only',
    'contains_mixed_upper_lower_case',
    'contains_equal',
    'contains_slash',
    'contains_dot',
    'contains_colon',
    'contains_special_chars',
]
num_per_hash = 500

alphabet = "abcdefghijklmnopqrstuvwxyz"
letter_to_index = dict(zip(alphabet, range(len(alphabet))))
index_to_letter = dict(zip(range(len(alphabet)), alphabet))

def create_row(hash, hash_type):
    return [
        hash_type,
        hash,
        get_scheme(hash),
        len(hash),
        contains_bit_only(hash),
        contains_decimal_only(hash),
        contains_hex_only(hash),
        contains_alpha_only(hash),
        contains_upper_case_only(hash),
        contains_lower_case_only(hash),
        contains_mixed_upper_lower_case(hash),
        contains_equal(hash),
        contains_slash(hash),
        contains_dot(hash),
        contains_colon(hash),
        contains_special_chars(hash),
    ]


def get_scheme(chars):  
    scheme = re.search("^(\$[0-9a-zA-Z]+\$|\{[0-9a-zA-Z]+\})", chars)
    if scheme is None:
        return "None"
    else:
        return scheme.group(0)


def contains_bit_only(chars):
    return int(re.search("[^01]", chars) is None)


def contains_decimal_only(chars):
    return int(re.search("[^0-9]", chars) is None)


def contains_hex_only(chars):
    for ch in chars:
        if re.match("[0-9a-fA-F]", ch) is None:
            return int(False)
    return int(True)


def contains_alpha_only(chars):
    return int(chars.isalpha())


def contains_upper_case_only(chars):
    return int(chars.isupper())


def contains_lower_case_only(chars):
    return int(chars.islower())


def contains_mixed_upper_lower_case(chars):
    upper = re.findall("[a-z]", chars)
    lower = re.findall("[A-Z]", chars)
    return int(len(upper) > 0 and len(lower) > 0)


def contains_equal(chars):
    return int(len(re.findall("\=", chars)) > 0)


def contains_slash(chars):
    return int(len(re.findall("\/", chars)) > 0)


def contains_dot(chars):
    return int(len(re.findall("\.", chars)) > 0)


def contains_colon(chars):
    return int(len(re.findall("\:", chars)) > 0)


def contains_special_chars(chars):
    return int(len(re.findall("\W", chars)) > 0)


def data_apr_md5_crypt(w):
    hash = apr_md5_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'Apache MD5 Crypt')


def data_argon2(w):
    hash = argon2.using(rounds=4).hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'Argon2')


def data_atbash(w):
    hash = ''.join([chr(ord('z') + ord('a') - ord(x)) for x in w])
    return create_row(hash, 'Atbash')


def data_atlassian_pbkdf2_sha1(w):
    hash = atlassian_pbkdf2_sha1.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'Atlassian PBKDF2 SHA1')


def data_base32(w):
    hash = base64.b32encode(w.encode('utf-8')).decode()
    return create_row(hash, 'Base32')


def data_base64(w):
    hash = base64.b64encode(w.encode('utf-8')).decode()
    return create_row(hash, 'Base64')


def data_bcrypt_2a(w):
    hash = bcrypt.hash(w.encode('utf-8'), ident="2a")
    return create_row(hash, 'BCrypt')


def data_bcrypt_2b(w):
    hash = bcrypt.hash(w.encode('utf-8'), ident="2b")
    return create_row(hash, 'BCrypt')


def data_binary(w):
    hash = ''.join(format(ord(x), 'b') for x in w)
    return create_row(hash, 'Binary')


def data_blake2b(w):
    hash = hashlib.blake2b()
    hash.update(w.encode('utf-8'))
    return create_row(hash.hexdigest(), 'BLAKE2b')


def data_blake2s(w):
    hash = hashlib.blake2s()
    hash.update(w.encode('utf-8'))
    return create_row(hash.hexdigest(), 'BLAKE2s')


def data_bsdi_crypt(w):
    hash = bsdi_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'BSDi Crypt')


def data_caesar(w):
    hash = ""
    s = 4 # shift pattern
    for i in range(len(w)):
        char = w[i]
        if (char.isupper()):
            hash += chr((ord(char) + s-65) % 26 + 65)
        else:
            hash += chr((ord(char) + s-97) % 26 + 97)
    return create_row(hash, 'Caesar')


def data_cisco_asa(w):
    hash = cisco_asa.hash(w.encode('utf-8'))
    return create_row(hash, 'CISCO-ASA MD5')


def data_cisco_pix(w):
    hash = cisco_pix.hash(w.encode('utf-8'))
    return create_row(hash, 'CISCO-PIX MD5')


def data_cisco_type7(w):
    hash = cisco_type7.hash(w.encode('utf-8'))
    return create_row(hash, 'CISCO Type 7')


def data_crc16(w):
    hash = str(fastcrc.crc16.xmodem(w.encode('utf-8')))
    return create_row(hash, 'CRC-16')


def data_crc32(w):
    hash = str(fastcrc.crc32.aixm(w.encode('utf-8')))
    return create_row(hash, 'CRC-32')


def data_crc64(w):
    hash = str(fastcrc.crc64.ecma_182(w.encode('utf-8')))
    return create_row(hash, 'CRC-64')


def data_decimal(w):
    hash = ''.join(format(ord(x), 'd') for x in w)
    return create_row(hash, 'Decimal')


def data_descrypt(w):
    hash = des_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'DES Crypt')


def data_django_argon2(w):
    hash = django_argon2.hash(w.encode('utf-8'))
    return create_row(hash, 'Django Argon2')


def data_django_bcrypt(w):
    hash = django_bcrypt.hash(w.encode('utf-8'))
    return create_row(hash, 'Django BCrypt')


def data_django_bcrypt_sha256(w):
    hash = django_bcrypt_sha256.hash(w.encode('utf-8'))
    return create_row(hash, 'Django BCrypt SHA256')


def data_django_des_crypt(w):
    hash = django_des_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'Django DES Crypt')


def data_django_pbkdf2_sha1(w):
    hash = django_pbkdf2_sha1.hash(w.encode('utf-8'))
    return create_row(hash, 'Django PBKDF2 SHA1')


def data_django_pbkdf2_sha256(w):
    hash = django_pbkdf2_sha256.hash(w.encode('utf-8'))
    return create_row(hash, 'Django PBKDF2 SHA256')

def data_django_salted_md5(w):
    hash = django_salted_md5.hash(w.encode('utf-8'))
    return create_row(hash, 'Django salted MD5')


def data_django_salted_sha1(w):
    hash = django_salted_sha1.hash(w.encode('utf-8'))
    return create_row(hash, 'Django salted SHA1')


def data_grub_pbkdf2_sha512(w):
    hash = grub_pbkdf2_sha512.hash(w.encode('utf-8'))
    return create_row(hash, 'Grub PBKDF2 SHA512')


def data_hex(w):
    hash = ''.join(format(ord(x), 'x') for x in w)
    return create_row(hash, 'Hex')


def data_hmac_sha1(w):
    secret = b'secret'
    hash = HMAC.new(secret, digestmod=SHA1)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'HMAC-SHA1')


def data_hmac_sha256(w):
    secret = b'secret'
    hash = HMAC.new(secret, digestmod=SHA256)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'HMAC-SHA256')


def data_hmac_sha512(w):
    secret = b'secret'
    hash = HMAC.new(secret, digestmod=SHA512)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'HMAC-SHA512')


def data_keccak_224(w):
    hash = keccak.new(digest_bits=224)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'Keccak-224')


def data_keccak_256(w):
    hash = keccak.new(digest_bits=256)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'Keccak-256')


def data_keccak_384(w):
    hash = keccak.new(digest_bits=384)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'Keccak-384')


def data_keccak_512(w):
    hash = keccak.new(digest_bits=512)
    hash.update(w.encode('utf-8'))
    hash = hash.hexdigest()
    return create_row(hash, 'Keccak-512')


def data_ldap_md5(w):
    hash = ldap_md5.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'LDAP MD5')


def data_ldap_salted_md5(w):
    hash = ldap_salted_md5.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'LDAP salted MD5')


def data_ldap_salted_sha1(w):
    hash = ldap_salted_sha1.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'LDAP salted SHA1')


def data_ldap_salted_sha256(w):
    hash = ldap_salted_sha256.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'LDAP salted SHA256')


def data_ldap_salted_sha512(w):
    hash = ldap_salted_sha512.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'LDAP salted SHA512')


def data_ldap_sha1(w):
    hash = ldap_sha1.hash(w.encode('utf-8'))
    hash = re.sub('\'', '', hash)
    return create_row(hash, 'LDAP SHA1')
    

def data_lm(w):
    hash = lmhash.hash(w.encode('utf-8'))
    return create_row(hash, 'LM')


def data_md4(w):
    hash = hashlib.new('md4', w.encode('utf-8')).hexdigest()
    return create_row(hash, 'MD4')


def data_md5(w):
    hash = hashlib.md5(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'MD5')


def data_md5_crypt(w):
    hash = md5_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'md5crypt')


def data_mssql2000(w):
    hash = mssql2000.hash(w.encode('utf-8'))
    return create_row(hash, 'MSSQL 2000')


def data_mssql2005(w):
    hash = mssql2005.hash(w.encode('utf-8'))
    return create_row(hash, 'MSSQL 2005')


def data_mysql323(w):
    hash = mysql323.hash(w.encode('utf-8'))
    return create_row(hash, 'MySQL 3.2.3')


def data_mysql41(w):
    hash = mysql41.hash(w.encode('utf-8'))
    return create_row(hash, 'MySQL 4.1')


def data_ntlm(w):
    hash = hashlib.new('md4', w.encode('utf-16le')).hexdigest()
    return create_row(hash, 'NTLM')


def data_oracle10(w):
    hash = oracle10.hash(w.encode('utf-8'), user="user")
    return create_row(hash, 'Oracle 10g')


def data_oracle11(w):
    hash = oracle11.hash(w.encode('utf-8'))
    return create_row(hash, 'Oracle 11g')


def data_pbkdf2_hmac_sha256(w):
    hash = hashlib.pbkdf2_hmac('SHA256', w.encode('utf-8'), b'salt'*2, 1000).hex()
    return create_row(hash, 'PBKDF2-HMAC-SHA256')


def data_pbkdf2_hmac_sha512(w):
    hash = hashlib.pbkdf2_hmac('SHA512', w.encode('utf-8'), b'salt'*2, 1000).hex()
    return create_row(hash, 'PBKDF2-HMAC-SHA512')


def data_phpass(w):
    hash = phpass.hash(w.encode('utf-8'))
    return create_row(hash, 'PHPass')


def data_postgres_md5(w):
    hash = postgres_md5.hash(w.encode('utf-8'), user="user")
    return create_row(hash, 'PostgreSQL MD5')


def data_rot13(w):
    hash = codecs.encode(w, 'rot_13')
    return create_row(hash, 'ROT13')


def data_rot47(w):
    chars = []
    for ch in range(len(w)):
        ord_val = ord(w[ch])
        if ord_val >= 33 and ord_val <= 126:
            chars.append(chr(33 + ((ord_val + 14) % 94)))
        else:
            chars.append(w[ch])
    hash = ''.join(chars)
    return create_row(hash, 'ROT47')


def data_scram(w):
    hash = scram.hash(w.encode('utf-8'))
    return create_row(hash, 'SCRAM')


def data_scrypt(w):
    hash = scrypt.hash(w.encode('utf-8'))
    return create_row(hash, 'SCrypt')


def data_sha1(w):
    hash = hashlib.sha1(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA1')


def data_sha1_crypt(w):
    hash = sha1_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'sha1crypt')


def data_sha224(w):
    hash = hashlib.sha224(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA224')


def data_sha256(w):
    hash = hashlib.sha256(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA256')


def data_sha256_crypt(w):
    hash = sha256_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'sha256crypt')


def data_sha384(w):
    hash = hashlib.sha384(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA384')


def data_sha512(w):
    hash = hashlib.sha512(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA512')


def data_sha512_crypt(w):
    hash = sha512_crypt.hash(w.encode('utf-8'))
    return create_row(hash, 'sha512crypt')


def data_sha3_224(w):
    hash = hashlib.sha3_224(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-224')


def data_sha3_256(w):
    hash = hashlib.sha3_256(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-256')


def data_sha3_384(w):
    hash = hashlib.sha3_384(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-384')


def data_sha3_512(w):
    hash = hashlib.sha3_512(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-512')


def data_vigenere(w):
    hash = ""
    key = "key"

    try:
        split_w = [
            w[i : i + len(key)] for i in range(0, len(w), len(key))
        ]

        for s in split_w:
            i = 0
            for letter in s:
                number = (letter_to_index[letter] + letter_to_index[key[i]]) % len(alphabet)
                hash += index_to_letter[number]
                i += 1
        return create_row(hash, 'Vigenere')
    except:
        print(f"{w}: Cannot generate Vigenere Cipher.")
        return None


def create_datas(w):
    datas = []
    datas.append(data_apr_md5_crypt(w))
    datas.append(data_argon2(w))
    datas.append(data_atbash(w))
    datas.append(data_atlassian_pbkdf2_sha1(w))
    datas.append(data_base32(w))
    datas.append(data_base64(w))
    datas.append(data_bcrypt_2a(w))
    datas.append(data_bcrypt_2b(w))
    datas.append(data_binary(w))
    datas.append(data_blake2b(w))
    datas.append(data_blake2s(w))
    datas.append(data_bsdi_crypt(w))
    datas.append(data_caesar(w))
    datas.append(data_cisco_asa(w))
    datas.append(data_cisco_pix(w))
    datas.append(data_cisco_type7(w))
    datas.append(data_crc16(w))
    datas.append(data_crc32(w))
    datas.append(data_crc64(w))
    datas.append(data_decimal(w))
    datas.append(data_descrypt(w))
    datas.append(data_django_argon2(w))
    datas.append(data_django_bcrypt(w))
    datas.append(data_django_bcrypt_sha256(w))
    datas.append(data_django_des_crypt(w))
    datas.append(data_django_pbkdf2_sha1(w))
    datas.append(data_django_pbkdf2_sha256(w))
    datas.append(data_django_salted_md5(w))
    datas.append(data_django_salted_sha1(w))
    datas.append(data_grub_pbkdf2_sha512(w))
    datas.append(data_hex(w))
    datas.append(data_hmac_sha1(w))
    datas.append(data_hmac_sha256(w))
    datas.append(data_hmac_sha512(w))
    datas.append(data_keccak_224(w))
    datas.append(data_keccak_256(w))
    datas.append(data_keccak_384(w))
    datas.append(data_keccak_512(w))
    datas.append(data_ldap_md5(w))
    datas.append(data_ldap_salted_md5(w))
    datas.append(data_ldap_salted_sha1(w))
    datas.append(data_ldap_salted_sha256(w))
    datas.append(data_ldap_salted_sha512(w))
    datas.append(data_ldap_sha1(w))
    datas.append(data_lm(w))
    datas.append(data_md4(w))
    datas.append(data_md5(w))
    datas.append(data_md5_crypt(w))
    datas.append(data_mssql2000(w))
    datas.append(data_mssql2005(w))
    datas.append(data_mysql323(w))
    datas.append(data_mysql41(w))
    datas.append(data_ntlm(w))
    datas.append(data_oracle10(w))
    datas.append(data_oracle11(w))
    datas.append(data_pbkdf2_hmac_sha256(w))
    datas.append(data_pbkdf2_hmac_sha512(w))
    datas.append(data_phpass(w))
    datas.append(data_postgres_md5(w))
    datas.append(data_rot13(w))
    datas.append(data_rot47(w))
    datas.append(data_scram(w))
    datas.append(data_scrypt(w))
    datas.append(data_sha1(w))
    datas.append(data_sha1_crypt(w))
    datas.append(data_sha224(w))
    datas.append(data_sha256(w))
    datas.append(data_sha256_crypt(w))
    datas.append(data_sha384(w))
    datas.append(data_sha512(w))
    datas.append(data_sha512_crypt(w))
    datas.append(data_sha3_224(w))
    datas.append(data_sha3_256(w))
    datas.append(data_sha3_384(w))
    datas.append(data_sha3_512(w))

    d_vigenere = data_vigenere(w)
    if d_vigenere is not None:
        datas.append(data_vigenere(w))

    return datas


def proc(word):
    return create_datas(word)


def write_csv(filepath, header, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(data)


def main():
    start = time.time()

    datas = []
    
    with codecs.open('/usr/share/wordlists/rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
        words = [w.rstrip() for w in f.readlines()]

    words = words[0:num_per_hash]
    print(f"words length is {len(words)}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(proc, word) for word in words]
        print(f"Executing total {len(futures)} jobs")
        for future in concurrent.futures.as_completed(futures):
            datas += future.result()
    
    # Data ratio (train:test)
    ratio = int(len(datas) * 3/4)
    datas_train = datas[0:ratio]
    datas_test = datas[ratio:]

    write_csv(dataset_path + 'hashes_train.csv', header, datas_train)
    write_csv(dataset_path + 'hashes_test.csv', header, datas_test)

    print(f"Length of datas_train: {len(datas_train)}")
    print(f"Length of datas_test: {len(datas_test)}")

    print("Generated the hashes dataset successfully.")

    end = time.time()
    print("Process time: %.2f seconds" % (end - start))


if __name__ == "__main__":
    main()