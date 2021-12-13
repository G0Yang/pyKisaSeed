from kisaSeed.kisaSeed import *

if __name__ == "__main__":
    text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum sit amet ultrices purus. Integer " \
           "cursus sit amet diam sagittis porttitor. Praesent viverra, erat at tincidunt ornare, mauris arcu " \
           "dignissim leo, faucibus dapibus est nisl ac neque. Etiam pulvinar sit amet nunc ac vulputate. Vestibulum " \
           "accumsan interdum ante ac consectetur. Aliquam ut mattis arcu. Aliquam a arcu vel mauris hendrerit " \
           "molestie. Phasellus rhoncus volutpat odio, eget mattis nisi maximus et. Suspendisse potenti. Aliquam " \
           "convallis suscipit risus, eget finibus velit fermentum eu. Suspendisse hendrerit metus magna, " \
           "id mattis leo interdum id. Donec bibendum arcu eget sem faucibus, non aliquam tortor tempor. Maecenas " \
           "facilisis mauris a eros aliquet, non euismod mi ullamcorper. Maecenas lobortis sagittis urna sit amet " \
           "viverra. Cras dignissim, libero at imperdiet elementum, magna nisi facilisis ante, eget sodales odio nibh " \
           "sit amet sem. Proin nec ultrices nisl. Cras ut vestibulum ex. Nam vel ornare turpis. Sed metus lorem, " \
           "semper a condimentum a, luctus nec sem."
    iv = None
    encode_text = None
    decode_text = None
    tag = None
    tweak = None
    nonce = None

    key = generate_nonce(16)
    seed = KisaSeed(key)

    crypto_modes = [e for e in Modes]
    padding_modes = [e for e in PaddingModes]

    for crypto_mode in crypto_modes:
        print("------------ start ------------", "\ncrypto_mode:", crypto_mode)
        for padding_mode in padding_modes:
            if(len(text) < 8 and padding_mode == PaddingModes.PKCS5):
                continue

            print("padding_mode:", padding_mode)
            print("text:", text)

            padding_text = seed.padding(padding_mode, str.encode(text))
            print("padding_text:", padding_text)

            if crypto_mode in [Modes.CBC, Modes.OFB, Modes.CFB, Modes.CFB8]:
                iv = generate_nonce(16)
                encode_text, tag = seed.encode(crypto_mode, padding_text, iv=iv)
            if crypto_mode in [Modes.GCM]:
                iv = generate_nonce(12)
                additional_data = generate_nonce(16)
                encode_text, tag = seed.encode(crypto_mode, padding_text, iv=iv, additional_data=additional_data)
            if crypto_mode in [Modes.XTS]:
                key = generate_nonce(32)
                seed = KisaSeed(key)
                tweak = generate_nonce(16)
                encode_text, tag = seed.encode(crypto_mode, padding_text, tweak=tweak)
            if crypto_mode in [Modes.CTR]:
                nonce = generate_nonce(16)
                encode_text, tag = seed.encode(crypto_mode, padding_text, nonce=nonce)
            if crypto_mode in [Modes.ECB]:
                encode_text, tag = seed.encode(crypto_mode, padding_text)
            print("encode_text, tag:", encode_text, tag)

            if crypto_mode in [Modes.CBC, Modes.OFB, Modes.CFB, Modes.CFB8]:
                decode_text = seed.decode(crypto_mode, encode_text, iv=iv)
            if crypto_mode in [Modes.GCM]:
                decode_text = seed.decode(crypto_mode, encode_text, iv=iv, additional_data=additional_data, tag=tag)
            if crypto_mode in [Modes.XTS]:
                decode_text = seed.decode(crypto_mode, encode_text, tweak=tweak)
            if crypto_mode in [Modes.CTR]:
                decode_text = seed.decode(crypto_mode, encode_text, nonce=nonce)
            if crypto_mode in [Modes.ECB]:
                decode_text = seed.decode(crypto_mode, encode_text)
            print("decode_text:", decode_text)

            unpadding_text = seed.padding_flush(padding_mode, decode_text)
            print("unpadding_text:", unpadding_text.decode('utf-8'))
            print()
        print("------------ e n d ------------\n")
