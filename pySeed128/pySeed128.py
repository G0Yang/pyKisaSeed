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


class Seed128:
    def __init__(self, key: bytes):
        self.ENC_KEY_LEN: int = 16  # 128 bit
        self.check_type_bytes(key)
        self.seed = algorithms.SEED(key)
        self.AES = algorithms.AES(key)

    def setModes(self, mode: Modes):
        self.mode = mode

    def check_type_bytes(self, input: bytes):
        if type(input) == bytes:
            return True
        else:
            msg = "input type error"
            logging.error(msg)
            raise msg

    def check_encode_length(self, input: bytes):
        if len(input) % self.ENC_KEY_LEN == 0:
            return True
        else:
            msg = "input length error"
            logging.warning(msg)
            return False


    def mode_selector(self, mode: Modes, iv: bytes = None, nonce: bytes = None):
        if mode == Modes.CBC:
            return base.Cipher(self.seed, modes.CBC(iv), backend)
        elif mode == Modes.ECB:
            return base.Cipher(self.seed, modes.ECB(), backend)
        elif mode == Modes.OFB:
            return base.Cipher(self.seed, modes.OFB(iv), backend)
        elif mode == Modes.CFB:
            return base.Cipher(self.seed, modes.CFB(iv), backend)
        elif mode == Modes.XTS:
            msg = "not supported this mode"
            logging.error(msg)
            raise msg
        elif mode == Modes.CFB8:
            return base.Cipher(self.AES, modes.CFB8(iv))
        elif mode == Modes.CTR:
            return base.Cipher(self.AES, modes.CTR(nonce))
        elif mode == Modes.GCM:
            msg = "not supported this mode"
            logging.error(msg)
            raise msg
        else:
            msg = "Invalid Encryption mode"
            logging.error(msg)
            raise msg

    # PKCS#5 and PKCS#7 Padding
    # Filled with left padding length like 0x01, 0x02, 0x03...
    def padding(self, mode: PaddingModes, byte: bytes):
        self.check_type_bytes(byte)
        if mode == PaddingModes.PKCS5:
            ENC_KEY_LEN_HELF = int(self.ENC_KEY_LEN / 2)
            padding_len = ENC_KEY_LEN_HELF - (len(byte) % ENC_KEY_LEN_HELF)
            byte += bytes([padding_len]) * (padding_len)
            return byte
        elif mode == PaddingModes.PKCS7:
            padding_len = self.ENC_KEY_LEN - (len(byte) % self.ENC_KEY_LEN)
            byte += bytes([padding_len]) * (padding_len)
            return byte
        elif mode == PaddingModes.NULL:
            padding_len = self.ENC_KEY_LEN - (len(byte) % self.ENC_KEY_LEN)
            byte += bytes(b"\x00" * padding_len)
            return byte
        else:
            msg = "Invalid Padding mode"
            logging.error(msg)
            raise msg

    def padding_flush(self, mode: PaddingModes, byte: bytes):
        self.check_type_bytes(byte)
        if mode == PaddingModes.PKCS5:
            return byte[: len(byte) - byte[-1]]
        elif mode == PaddingModes.PKCS7:
            return byte[: len(byte) - byte[-1]]
        elif mode == PaddingModes.NULL:
            if byte[-1] != 0:
                return byte
            else:
                return self.padding_flush(mode, byte[: len(byte) - 1])
        else:
            msg = "Invalid Padding Flush mode"
            logging.error(msg)
            raise msg

    def encode(self, mode: Modes, byte: bytes, iv: bytes = None, additional_data: bytes = None, nonce: bytes = None):
        self.check_type_bytes(byte)
        self.check_encode_length(byte)
        cipher = self.mode_selector(mode, iv, nonce)
        if mode == Modes.GCM:
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(additional_data)
            return (encryptor.update(byte) + encryptor.finalize(), encryptor.tag)
        else:
            return (
                cipher.encryptor().update(byte) + cipher.encryptor().finalize(),
                None,
            )

    def decode(self, mode: Modes, byte: bytes, iv: bytes = None, tag: bytes = None, nonce: bytes = None):
        self.check_type_bytes(byte)
        cipher = self.mode_selector(mode, iv, nonce)
        if mode == Modes.GCM:
            decryptor = cipher.decryptor()
            decryptor.finalize_with_tag(tag)
            return decryptor.update(byte) + decryptor.finalize()
        else:
            return cipher.decryptor().update(byte) + cipher.decryptor().finalize()
