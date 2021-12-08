import base64

from pySeed128 import pySeed128

if __name__ == "__main__":
    text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum sit amet ultrices purus. Integer cursus sit amet diam sagittis porttitor. Praesent viverra, erat at tincidunt ornare, mauris arcu dignissim leo, faucibus dapibus est nisl ac neque. Etiam pulvinar sit amet nunc ac vulputate. Vestibulum accumsan interdum ante ac consectetur. Aliquam ut mattis arcu. Aliquam a arcu vel mauris hendrerit molestie. Phasellus rhoncus volutpat odio, eget mattis nisi maximus et. Suspendisse potenti. Aliquam convallis suscipit risus, eget finibus velit fermentum eu. Suspendisse hendrerit metus magna, id mattis leo interdum id. Donec bibendum arcu eget sem faucibus, non aliquam tortor tempor. Maecenas facilisis mauris a eros aliquet, non euismod mi ullamcorper. Maecenas lobortis sagittis urna sit amet viverra. Cras dignissim, libero at imperdiet elementum, magna nisi facilisis ante, eget sodales odio nibh sit amet sem. Proin nec ultrices nisl. Cras ut vestibulum ex. Nam vel ornare turpis. Sed metus lorem, semper a condimentum a, luctus nec sem."
    ivString = "1234567890ABCDEF"
    keyString = "FEDCBA0987654321"

    iv = str.encode(ivString)
    key = str.encode(keyString)

    seed = pySeed128.Seed128(iv, key)

    crypto_mode = seed.Modes.CFB
    padding_mode = seed.PaddingModes.PKCS7
    additional_data = seed.generate_nonce(16)

    print("crypto_mode:", crypto_mode)
    print("padding_mode:", padding_mode)
    print("additional_data:", additional_data)

    print("\ntext:\n", type(text), len(text), text)

    byte_text = str.encode(text)
    print("\nbyte_text:\n", type(byte_text), len(byte_text), byte_text)

    pad_text = seed.padding(padding_mode, byte_text)
    print("\npad_text:\n", type(pad_text), len(pad_text), pad_text)

    seed_encoded_text, tag = seed.encode(crypto_mode, pad_text, additional_data)
    print(
        "\nseed_encoded_text:\n",
        type(seed_encoded_text),
        len(seed_encoded_text),
        seed_encoded_text,
    )

    base64_seed_encoded_text = base64.b64encode(seed_encoded_text)
    print(
        "\nbase64_seed_encoded_text:\n",
        type(base64_seed_encoded_text),
        len(base64_seed_encoded_text),
        base64_seed_encoded_text,
    )

    base64_decoded_text = base64.b64decode(base64_seed_encoded_text)
    print(
        "\nbase64_decoded_text:\n",
        type(base64_decoded_text),
        len(base64_decoded_text),
        base64_decoded_text,
    )

    seed_base64_decoded_text = seed.decode(crypto_mode, base64_decoded_text, tag)
    print(
        "\nseed_base64_decoded_text:\n",
        type(seed_base64_decoded_text),
        len(seed_base64_decoded_text),
        seed_base64_decoded_text,
    )

    del_pad_text = seed.padding_flush(padding_mode, seed_base64_decoded_text)
    print("\ndel_pad_text:\n", type(del_pad_text), len(del_pad_text), del_pad_text)

    decode_text = del_pad_text.decode()
    print("\ndecode_text:\n", type(decode_text), len(decode_text), decode_text)
