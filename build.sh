#!/bin/bash
pip install --upgrade pip
pip install -r requirements.txt
pip install --no-cache-dir --upgrade pip setuptools wheel
pip install --no-cache-dir --force-reinstall cryptography pyOpenSSL

