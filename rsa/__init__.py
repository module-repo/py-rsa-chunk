import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


class RSAUtil(object):
    """ RSA Chunk Util """

    def __init__(self, private_file, public_file):
        if public_file:
            self.public_key = open(public_file).read()
        if private_file:
            self.private_key = open(private_file).read()

    def encrypt(self, msg):
        """ RSA Encrypt """

        if not self.public_key:
            print('missing public key file')
            return
        key = RSA.importKey(self.public_key)
        size = key.size_in_bytes() - 11
        # 分段加密
        pk = PKCS1_v1_5.new(key)
        encrypt_text = []
        for i in range(0, len(msg), size):
            cont = msg[i:i + size]
            encrypt_text.append(pk.encrypt(cont.encode()))
        # 加密完进行拼接
        cipher_text = b''.join(encrypt_text)
        # base64进行编码
        result = base64.b64encode(cipher_text)
        return result.decode()

    def decrypt(self, msg):
        """ RSA Decrypt """

        if not self.private_key:
            print('missing private key file')
            return
        msg = base64.b64decode(msg)
        # 获取私钥
        rsa_key = RSA.importKey(self.private_key)
        size = rsa_key.size_in_bytes()
        cipher = PKCS1_v1_5.new(rsa_key)
        # 进行解密
        text = []
        for i in range(0, len(msg), size):
            cont = msg[i:i + size]
            text.append(cipher.decrypt(cont, 1))
        text = b''.join(text)
        return text.decode()
