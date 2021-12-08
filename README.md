# pySeed128
KISA Seed 128 encrypt python package

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
    from pySeed128 import pySeed128
    pySeed128.Seed128(iv, key)