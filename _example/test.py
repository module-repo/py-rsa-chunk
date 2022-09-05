#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Date: 2022/9/5
# File: test.py

from rsa import RSAUtil

if __name__ == '__main__':
    r = RSAUtil(private_file='pri.key', public_file='pub.pem')
    print(r.decrypt(r.encrypt('test')))
