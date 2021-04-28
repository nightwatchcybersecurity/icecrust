# icecrust
[![PyPI version](https://badge.fury.io/py/icecrust.svg)](https://badge.fury.io/py/icecrust)
[![Build Status](https://github.com/nightwatchcybersecurity/icecrust/workflows/Test%20package/badge.svg?branch=master)](https://github.com/nightwatchcybersecurity/icecrust/actions)
[![codecov](https://codecov.io/gh/nightwatchcybersecurity/icecrust/branch/master/graph/badge.svg)](https://codecov.io/gh/nightwatchcybersecurity/icecrust)
![GitHub](https://img.shields.io/github/license/nightwatchcybersecurity/icecrust.svg)

A tool for verification of software downloads using hashes and/or PGP.

## Requirements
Python 3 is required and you can find all required modules in the **requirements.txt** file.
Only tested on Python 3.7 but should work on other 3.x releases.

You must also have GnuPG installed.

## Installation
You can install this via PIP as follows:
```
pip install icecrust
icecrust version
```
To download and run manually, do the following:
```
git clone https://github.com/nightwatchcybersecurity/icecrust.git
cd icecrust
pip install -r requirements.txt
python -m icecrust.cli
```

## How to use 
There are two main types of operations this utility can do:
1. Verify a file against a PGP detached signature, using a key ID or a file containing keys.
2. Verify a file against a PGP-signed checksum, using a key ID or file containing keys.

If you are using a key ID, this utility will attempt to connect to a PGP server. If you use a keyfile,
the verification will be done entirely off line.

This utility will not modify or use your PGP keyrings, instead a temporary directory is created for this purpose.
While this is less efficient and somewhat less secure, it is easier for a lot of users since it avoids the
complexity of managing PGP keys.

### Verifying a detached signature
First download the software to be verified and its signature:
```
curl -O https://www.example.com/software.zip
curl -O https://www.example.com/software.zip.sig
```

Verify using a key ID:
```
icecrust pgpverify_with_keyid software.zip software.zip.sig --keyid 12345 --keyserver pgp.example.com
```

If you want to use a keyfile, you must download it or provide it, then verify:
```
curl -O https://www.example.com/project_keys.txt
icecrust pgpverify_with_keyfile software.zip software.zip.sig --keyfile project_keys.txt
```

### Verifying using a PGP-signed checksum file
First download the software to be verified, its checksum and signatures:
```
curl -O https://www.example.com/software.zip
curl -O https://www.example.com/software.CHECKSUMS.txt
curl -O https://www.example.com/software.CHECKSUMS.txt.sig
```

Verify using a key ID (algorithm is option and defaults to SHA-256):
```
icecrust checksumverify_with_keyid software.zip software.CHECKSUMS.txt software.CHECKSUMS.txt.sig --keyid 12345 --keyserver pgp.example.com -algorithm sha256
```

If you want to use a keyfile, you must download it or provide it, then verify:
```
curl -O https://www.example.com/project_keys.txt
icecrust checksumverify_with_keyid software.zip software.CHECKSUMS.txt software.CHECKSUMS.txt.sig --keyfile project_keys.txt
```

## Sample output
Any errors will result in a non-zero return.

Display installed version:
```
user@localhost:~/$ icecrust --version
icecrust, version 0.1.0
```

Example of detached signature verification:
```
signature valid
```

Example of checksum verification with key ID:
```
signature valid
File checksum verified against the checksums file
```

# Development Information

## Reporting bugs and feature requests
Please use the GitHub issue tracker to report issues or suggest features:
https://github.com/nightwatchcybersecurity/icecrust

You can also send emai to ***research /at/ nightwatchcybersecurity [dot] com***

## Wishlist
- Add more unit tests
- Add warning checks for when URLs are being served from the same site
- Add help for all CLI options

## About the name
"Ice Crust" or "Ледяная Кора" is a magical spell for mental protection
(from the book "Last Watch" / "Последний Дозор" by Sergei Lukyanenko)
