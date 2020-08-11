# easysocks5

***easysocks5*** is a simple SOCKS5 implementation based on AsyncIO.

Currently only SOCKS5 without authentication and CONNECT command are supported.

## Requirement
Python >= 3.7

## Quick guide

### Install from PyPI
```bash
python3 -m pip install easysocks5
python -m easysocks5.server -H 127.0.0.1 -P 8888
```

### Get latest version from GitHub
```bash
git clone https://github.com/frankurcrazy/easysocks5
cd easysocks5 && python -m easysocks5.server -H 127.0.0.1 -P 8888
```

## License
MIT
