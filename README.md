# icetrust
![PyPI](https://img.shields.io/pypi/v/icetrust)
[![Test package](https://github.com/nightwatchcybersecurity/icetrust/actions/workflows/ci-develop.yml/badge.svg)](https://github.com/nightwatchcybersecurity/icetrust/actions/workflows/ci-develop.yml)
[![Extra tests on main branch only](https://github.com/nightwatchcybersecurity/icetrust/actions/workflows/ci-main.yml/badge.svg)](https://github.com/nightwatchcybersecurity/icetrust/actions/workflows/ci-main.yml)
[![codecov](https://codecov.io/gh/nightwatchcybersecurity/icetrust/branch/main/graph/badge.svg?token=YvekypYOfw)](https://codecov.io/gh/nightwatchcybersecurity/icetrust)
![GitHub](https://img.shields.io/github/license/nightwatchcybersecurity/icetrust.svg)
![PyPI - Downloads](https://img.shields.io/pypi/dm/icetrust)

# What is this?
A tool for verification of software downloads using checksums and/or PGP.

This tool is intended to make verification of downloads easier. Development of this project 
was prompted by [the recent supply chain attack against codecov.io](https://about.codecov.io/security-update/).

## Requirements
Python 3 is required and you can find all required modules in the **requirements.txt** file.
Only tested on Python 3.9 but should work on other 3.x releases.

You also must have GnuPG installed.

## Installation
Check if GnuPG is installed:
```
gpg --version
```

Install this project via PIP:
```
pip install icetrust
icetrust --version
```

Alternatively, you can download and run manually:
```
git clone https://github.com/nightwatchcybersecurity/icetrust.git
cd icetrust
pip install -r requirements.txt
python -m icetrust.cli
```

# How to use 
There are two main modes that this tool can be used in:
1. For project owners: ["canary" mode](CANARY.md) can be used to
   download and verify project files on a regular basis 
   to detect supply chain attacks.
2. For end users: this tool can be used for verification of
   already downloaded files against checksums or PGP.

If you are using a PGP key ID, this utility will attempt to connect to a PGP server. If you use a keyfile,
the verification will be done entirely off-line.  This utility will not modify or use your PGP keyrings, instead a temporary directory is created for this purpose.
While this is less efficient and somewhat less secure, it is easier for a lot of users since it avoids the
complexity of managing PGP keys.

***NOTE: if you are comfortable with using GnuPG and native OS command line tools for
verification, please use those instead. This tool is only intended for users who are not yet
comfortable with that approach.***

## Canary Mode
See [CANARY.md](CANARY.md) for help. 

Live demos can be viewed here:
- [icetrust_dashboard.nightwatchcybersecurity.com](https://icetrust_dashboard.nightwatchcybersecurity.com)
- [icetrust_uptime.nightwatchcybersecurity.com](https://icetrust_uptime.nightwatchcybersecurity.com)


## Verification modes
This tool offers the following verification modes to verify downloaded files:
1. ***compare_files*** - compares a downloaded file against another copy obtained from another
   source/location, using checksums.
2. ***checksum*** - verifies a downloaded file against a hardcoded checksum value.
3. ***checksumfile*** - verifies a downloaded file against checksum values in a separate
   file. The file follows the format used by SHASUM.
4. ***pgp*** - verifies a downloaded file against a detached PGP signature in a separate
   file. This uses PGP keys provided via a file or a key ID/server name.
5. ***pgpchecksumfile*** - verifies a downloaded file against checksum values in a separate
   file. That file is first verified via a detached PGP signature using PGP keys provided
   via a file or a key ID/server name.
   
To view more details on the verification process, use the "--verbose" option.

### compare_files
First download the software to be verified and its second copy:
```
curl -O https://www1.example.com/software1.zip
curl -O https://www2.example.com/software2.zip
```

Compare the files (SHA-256 is used behind the scenes):
```
icetrust compare_files software1.zip software2.zip
```

### checksum
First download the software to be verified:
```
curl -O https://www.example.com/software.zip
```

Verify using the checksum value (unless specified, SHA-256 is used):
```
icetrust checksum software.zip foobarchecksumvaluefoobar
```

### checksumfile
First download the software to be verified and its checksum file:
```
curl -O https://www1.example.com/software.zip
curl -O https://www2.example.com/software.CHECKSUMS.txt
```

Verify using the checksum file (unless specified, SHA-256 is used):
```
icetrust checksumfile software.zip software.CHECKSUMS.txt
```

### pgp
First download the software to be verified and its signature file:
```
curl -O https://www.example.com/software.zip
curl -O https://www.example.com/software.zip.sig
```

Verify using a key ID:
```
icetrust pgp software.zip software.zip.sig --keyid 12345 --keyserver pgp.example.com
```

If you want to use a keyfile, you must download it or provide it, then verify:
```
curl -O https://keys.example.com/project_keys.txt
icetrust pgp software.zip software.zip.sig --keyfile project_keys.txt
```

### pgpchecksumfile
First download the software to be verified, its checksum and signatures:
```
curl -O https://www.example.com/software.zip
curl -O https://www.example.com/software.CHECKSUMS.txt
curl -O https://www.example.com/software.CHECKSUMS.txt.sig
```

Verify using a key ID (unless specified, SHA-256 is used):
```
icetrust pgpchecksumfile software.zip software.CHECKSUMS.txt software.CHECKSUMS.txt.sig --keyid 12345 --keyserver pgp.example.com
```

If you want to use a keyfile, you must download it or provide it, then verify:
```
curl -O https://keys.example.com/project_keys.txt
icetrust pgpchecksumfile software.zip software.CHECKSUMS.txt software.CHECKSUMS.txt.sig --keyfile project_keys.txt
```

# Sample output and automation
Display installed version:
```
user@localhost:~/$ icetrust --version
icetrust, version 0.1.0
```

Example of successful verification
```
File verified
```

Example of failed verification
```
ERROR: File cannot be verified!
```

Successful verification will return 0. Any errors or failed verification
will result in a non-zero return.

# Development Information

## Reporting bugs and feature requests
Please use the GitHub issue tracker to report issues or suggest features:
https://github.com/nightwatchcybersecurity/icetrust

You can also send emai to ***research /at/ nightwatchcybersecurity [dot] com***

## Wishlist
- Add more unit tests

## About the name
The name "Ice Trust" is a play on words "Ice Crust" or "Ледяная Кора", which
is a magical spell for mental protection (from the book
"Last Watch" / "Последний Дозор" by Sergei Lukyanenko)
