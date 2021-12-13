from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import algorithms, base, modes
import logging
import random
from enum import Enum


class Modes(Enum):  # supply modes
    CBC: str = "CBC"
    ECB: str = "ECB"
    OFB: str = "OFB"
    CFB: str = "CFB"
    XTS: str = "XTS"
    CFB8: str = "CFB8"
    CTR: str = "CTR"
    GCM: str = "GCM"


class PaddingModes(Enum):  # supply modes
    PKCS5: str = "PKCS5"
    PKCS7: str = "PKCS7"
    NULL: str = "NULL"


def generate_nonce(length: int):
    return str.encode("".join([str(random.randint(0, 9)) for i in range(length)]))


def _raise(msg):
    logging.error(msg)
    raise msg


class KisaSeed:
    name = "KisaSeed"

    def __init__(self, key: bytes):
        self.ENC_KEY_LEN: int = 16  # 128 bit
        self.check_type_bytes(key)
        self.AES = algorithms.AES(key)

    def check_type_bytes(self, data: bytes):
        if type(data) == bytes:
            return True
        else:
            _raise("input type error")

    def check_encode_length(self, data: bytes):
        if len(data) % self.ENC_KEY_LEN == 0:
            return True
        else:
            _raise("input length error")

    def mode_selector(self, mode: Modes, iv: bytes = None, nonce: bytes = None, tweak: bytes = None, tag: bytes = None):
        if mode == Modes.CBC:
            return base.Cipher(self.AES, modes.CBC(iv), backend)
        elif mode == Modes.ECB:
            return base.Cipher(self.AES, modes.ECB(), backend)
        elif mode == Modes.OFB:
            return base.Cipher(self.AES, modes.OFB(iv), backend)
        elif mode == Modes.CFB:
            return base.Cipher(self.AES, modes.CFB(iv), backend)
        elif mode == Modes.XTS:
            return base.Cipher(self.AES, modes.XTS(tweak), backend)
        elif mode == Modes.CFB8:
            return base.Cipher(self.AES, modes.CFB8(iv), backend)
        elif mode == Modes.CTR:
            return base.Cipher(self.AES, modes.CTR(nonce), backend)
        elif mode == Modes.GCM:
            return base.Cipher(self.AES, modes.GCM(iv, tag), backend)
        else:
            _raise("Invalid Encryption mode")

    # PKCS#5 and PKCS#7 Padding
    # Filled with left padding length like 0x01, 0x02, 0x03...
    def padding(self, mode: PaddingModes, data: bytes):
        self.check_type_bytes(data)
        if mode == PaddingModes.PKCS5:
            ENC_KEY_LEN_HELF = int(self.ENC_KEY_LEN / 2)
            padding_len = ENC_KEY_LEN_HELF - (len(data) % ENC_KEY_LEN_HELF)
            data += bytes([padding_len]) * (padding_len)
            return data
        elif mode == PaddingModes.PKCS7:
            padding_len = self.ENC_KEY_LEN - (len(data) % self.ENC_KEY_LEN)
            data += bytes([padding_len]) * (padding_len)
            return data
        elif mode == PaddingModes.NULL:
            padding_len = self.ENC_KEY_LEN - (len(data) % self.ENC_KEY_LEN)
            data += bytes(b"\x00" * padding_len)
            return data
        else:
            _raise("Invalid Padding mode")

    def padding_flush(self, mode: PaddingModes, data: bytes):
        self.check_type_bytes(data)
        if mode == PaddingModes.PKCS5:
            return data[: len(data) - data[-1]]
        elif mode == PaddingModes.PKCS7:
            return data[: len(data) - data[-1]]
        elif mode == PaddingModes.NULL:
            if data[-1] != 0:
                return data
            else:
                return self.padding_flush(mode, data[: len(data) - 1])
        else:
            _raise("Invalid Padding Flush mode")

    def encode(self, mode: Modes, data: bytes, iv: bytes = None, additional_data: bytes = None, tweak: bytes = None,
               nonce: bytes = None):
        self.check_type_bytes(data)
        if mode in [Modes.GCM]:
            cipher = self.mode_selector(mode, iv=iv)
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(additional_data)
            return (encryptor.update(data) + encryptor.finalize(), encryptor.tag)
        elif mode in [Modes.CBC, Modes.OFB, Modes.CFB, Modes.CFB8]:
            cipher = self.mode_selector(mode, iv=iv)
            return (cipher.encryptor().update(data) + cipher.encryptor().finalize(), None)
        elif mode in [Modes.XTS]:
            cipher = self.mode_selector(mode, tweak=tweak)
            return (cipher.encryptor().update(data) + cipher.encryptor().finalize(), None)
        elif mode in [Modes.CTR]:
            cipher = self.mode_selector(mode, nonce=nonce)
            return (cipher.encryptor().update(data) + cipher.encryptor().finalize(), None)
        elif mode in [Modes.ECB]:
            cipher = self.mode_selector(mode)
            return (cipher.encryptor().update(data) + cipher.encryptor().finalize(), None)
        else:
            _raise("not supported this mode")

    def decode(self, mode: Modes, data: bytes, iv: bytes = None, additional_data: bytes = None, tag: bytes = None,
               tweak: bytes = None, nonce: bytes = None):
        self.check_type_bytes(data)
        if mode in [Modes.GCM]:
            cipher = self.mode_selector(mode, iv=iv, tag=tag)
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(additional_data)
            return decryptor.update(data) + decryptor.finalize()
        elif mode in [Modes.CBC, Modes.OFB, Modes.CFB, Modes.CFB8]:
            cipher = self.mode_selector(mode, iv=iv)
            return cipher.decryptor().update(data) + cipher.decryptor().finalize()
        elif mode in [Modes.XTS]:
            cipher = self.mode_selector(mode, tweak=tweak)
            return cipher.decryptor().update(data) + cipher.decryptor().finalize()
        elif mode in [Modes.CTR]:
            cipher = self.mode_selector(mode, nonce=nonce)
            return cipher.decryptor().update(data) + cipher.decryptor().finalize()
        elif mode in [Modes.ECB]:
            cipher = self.mode_selector(mode)
            return cipher.decryptor().update(data) + cipher.decryptor().finalize()
        else:
            _raise("not supported this mode")
