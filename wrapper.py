from secp256k1 import PrivateKey
from secp256k1 import PublicKey
import secp256k1

def _int_to_big_endian(value):
    cs = []
    while value > 0:
        cs.append(chr(value % 256))
        value /= 256
    s = ''.join(reversed(cs))
    return s


def _big_endian_to_int(value):
    return int(value.encode('hex'), 16)


def _lzpad32(x):
    return '\x00' * (32 - len(x)) + x


def _encode_sig(v, r, s):
    assert isinstance(v, (int, long))
    assert v in (27, 28)
    # This fixes the one failing block test, but introduces four new
    # failing tests in transaction tests.
    # if not len(_int_to_big_endian(r)) == 32:
        # raise InvalidTransaction("Invalid signature values!")
    vb, rb, sb = v - 27, _int_to_big_endian(r), _int_to_big_endian(s)
    return _lzpad32(rb) + _lzpad32(sb), vb


def _decode_sig(sig):
    return sig[1] + 27, _big_endian_to_int(sig[0][0:32]), _big_endian_to_int(sig[0][32:64])


class Secp256k1_compact(object):
    def __init__(self):
        self.priv_key = PrivateKey()
        self.pub_key = PublicKey(pubkey=None, raw=False, flags=secp256k1.ALL_FLAGS)

    def ecdsa_compact_sign(self, msg32, privkey):
        if type(privkey) == unicode:
            privkey = privkey.encode('utf-8')
        self.priv_key.set_raw_privkey(privkey)
        sig = self.priv_key.ecdsa_sign_recoverable(msg32, raw=True)
        return self.priv_key.ecdsa_recoverable_serialize(sig)

    def ecdsa_compact_recover(self, msg32, sign):
        if not len(sign) == 2:
            sign = (sign[:64], ord(sign[64]))
        assert len(sign) == 2
        deserialized_sig = self.pub_key.ecdsa_recoverable_deserialize(sign[0], sign[1])
        self.pub_key.public_key = self.pub_key.ecdsa_recover(msg32, deserialized_sig, raw=True)
        return self.pub_key.serialize(compressed=False)

    def ecdsa_compact_verify(self, msg32, sign, pub):
        # Check if pubkey has been bin_electrum encoded.
        # If so, append \04 to the front of the key, to make sure the length is 65
        if len(pub) == 64:
            pub = '\04'+pub
        pub_k = PublicKey().deserialize(pub)
        pub_key = PublicKey(pub_k, raw=False, flags=secp256k1.ALL_FLAGS)
        der_sig = pub_key.ecdsa_recoverable_deserialize(sign[0], sign[1])
        raw_sig = pub_key.ecdsa_recoverable_convert(der_sig)
        return pub_key.ecdsa_verify(msg32, raw_sig, raw=True)


class Secp256k1_raw(object):
    def __init__(self):
        self.ecdsa = Secp256k1_compact()

    def ecdsa_raw_sign(self, msg32, privkey):
        return _decode_sig(self.ecdsa.ecdsa_compact_sign(msg32, privkey))

    def ecdsa_raw_recover(self, msg32, sign):
        v, r, s = sign
        return self.ecdsa.ecdsa_compact_recover(msg32, _encode_sig(*sign))

    def ecdsa_raw_verify(self, msg32, sign, pub):
        return self.ecdsa.ecdsa_compact_verify(msg32, _encode_sig(*sign), pub)
