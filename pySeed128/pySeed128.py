from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import algorithms, base, modes
import logging
import random
from enum import Enum


class Seed128:
    def __init__(self, iv: bytes, key: bytes):
        self.ENC_KEY_LEN: int = 16  # 128 bit
        self.check_type_bytes(iv)
        self.check_type_bytes(key)
        if len(iv) == len(key) == self.ENC_KEY_LEN:
            self.iv: bytes = iv
            self.key: bytes = key
            self.seed = algorithms.SEED(self.key)
        else:
            msg = ("Invalid initialize inputs", iv, key)
            logging.error(msg)
            raise msg

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

    def generate_nonce(self, length: int):
        return str.encode("".join([str(random.randint(0, 9)) for i in range(length)]))

    def mode_selector(self, mode: Modes):
        if mode == self.Modes.CBC:
            return base.Cipher(self.seed, modes.CBC(self.iv), backend)
        elif mode == self.Modes.ECB:
            return base.Cipher(self.seed, modes.ECB(), backend)
        elif mode == self.Modes.OFB:
            return base.Cipher(self.seed, modes.OFB(self.iv), backend)
        elif mode == self.Modes.CFB:
            return base.Cipher(self.seed, modes.CFB(self.iv), backend)
        elif mode == self.Modes.XTS:
            msg = "not supported this mode"
            logging.error(msg)
            raise msg
        elif mode == self.Modes.CFB8:
            msg = "not supported this mode"
            logging.error(msg)
            raise msg
        elif mode == self.Modes.CTR:
            msg = "not supported this mode"
            logging.error(msg)
            raise msg
        elif mode == self.Modes.GCM:
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
        if mode == self.PaddingModes.PKCS5:
            ENC_KEY_LEN_HELF = int(self.ENC_KEY_LEN / 2)
            padding_len = ENC_KEY_LEN_HELF - (len(byte) % ENC_KEY_LEN_HELF)
            byte += bytes([padding_len]) * (padding_len)
            return byte
        elif mode == self.PaddingModes.PKCS7:
            padding_len = self.ENC_KEY_LEN - (len(byte) % self.ENC_KEY_LEN)
            byte += bytes([padding_len]) * (padding_len)
            return byte
        elif mode == self.PaddingModes.NULL:
            padding_len = self.ENC_KEY_LEN - (len(byte) % self.ENC_KEY_LEN)
            byte += bytes(b"\x00" * padding_len)
            return byte
        else:
            msg = "Invalid Padding mode"
            logging.error(msg)
            raise msg

    def padding_flush(self, mode: PaddingModes, byte: bytes):
        self.check_type_bytes(byte)
        if mode == self.PaddingModes.PKCS5:
            return byte[: len(byte) - byte[-1]]
        elif mode == self.PaddingModes.PKCS7:
            return byte[: len(byte) - byte[-1]]
        elif mode == self.PaddingModes.NULL:
            if byte[-1] != 0:
                return byte
            else:
                return self.padding_flush(mode, byte[: len(byte) - 1])
        else:
            msg = "Invalid Padding Flush mode"
            logging.error(msg)
            raise msg

    def encode(self, mode: Modes, byte: bytes, additional_data: bytes = None):
        self.check_type_bytes(byte)
        self.check_encode_length(byte)
        cipher = self.mode_selector(mode)
        if mode == self.Modes.GCM:
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(additional_data)
            return (encryptor.update(byte) + encryptor.finalize(), encryptor.tag)
        else:
            return (
                cipher.encryptor().update(byte) + cipher.encryptor().finalize(),
                None,
            )

    def decode(self, mode: Modes, byte: bytes, tag: bytes = None):
        self.check_type_bytes(byte)
        cipher = self.mode_selector(mode)
        if mode == self.Modes.GCM:
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(tag)
            return decryptor.update(byte) + decryptor.finalize()
        else:
            return cipher.decryptor().update(byte) + cipher.decryptor().finalize()
