# pySeed128
KISA Seed 128 encrypt python package

Based on cryptography

## Build
    # on shell
    python3 -m pip install setuptools wheel
    python3 setup.py sdist bdist_wheel

## Upload pip
    # on shell
    python3 -m pip install twine
    python3 -m twine upload dist/*

## Usage
    # on python
    from kisaSeed.kisaSeed import *
    key = generate_nonce(16)
    seed = KisaSeed(key)

## Design Internals
- CBC
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/cbc.html
- OFB
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/ofb.html
- CFB
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/cfb.html
- CFB8
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/cfb.html#cfb8-aes128-encryption
- GCM
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/gcm.html
- XTS
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/xts.html
- CTR
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/ctr.html
- ECB
  - https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/ecb.html