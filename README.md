# socks5

***socks5*** is a simple SOCKS5 implementation based on AsyncIO.

Currently only SOCKS5 without authentication and CONNECT command are supported.

## Requirement
Python >= 3.7

## Quick guide

### Install from PyPI
```bash
python3 -m pip install simple-socks5
python -m socks5.server -H 127.0.0.1 -P 8888
```

### Get latest version from GitHub
```bash
git clone https://github.com/frankurcrazy/socks5
cd socks5 && python -m socks5.server -H 127.0.0.1 -P 8888
```

## License
MIT
