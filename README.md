# Loader

### Features
* No CRT library imports
* API hashing
* The encrypted payload is obtained by downloading from a C2
* AES256-CBC payload encryption using custom no table/data-dependent branches using ctaes
* Aes Key & Iv encryption
* Indirect syscalls
* Anti-Analysis functionality
* Version.dll sideloading

### Usage
* Hasher to calculate API hashes
* PayloadBuilder to generate a encrypted key and encrypt the payload
* XOR to generate a encrypted url
  
### Credits
* Maldev Academy (https://maldevacademy.com/)
* Tartarus-TpAllocInject (https://github.com/nettitude/Tartarus-TpAllocInject)
* ctaes (https://github.com/bitcoin-core/ctaes)
* AtomLdr (https://github.com/NUL0x4C/AtomLdr)

## Disclaimer
This repository is created for educational purposes only. Any legal responsibility belongs to the person or organization that uses it.
