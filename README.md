# Headless eduroam setup

This installer connects your device to an eduroam network.

This code is based on the official [eduroam linux installer](https://cat.eduroam.org/).

## How it works

 1. Create a file named _rapberry-config_ containing following information:
```
EDUROAM-USER = username@UNIBERN.ch

EDUROAM-PWD = userpasswd
```
 2. Execute the installer with `python eduroam-setup.py`

## Install dependencies

`pip install -r requirements.txt`

