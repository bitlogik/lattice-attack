#!/usr/bin/env python3

# Lattice ECDSA Attack : ECDSA and cryptographic library
# Copyright (C) 2021  Antoine Ferron - BitLogiK
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# Install cryptography
#  pip3 install cryptography
#   or
#  apt install python3-cryptography


import hashlib
import secrets

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec


CURVES_ORDER = {
    "SECP224R1": int(
        "2695994666715063979466701508701962594045780771442439172168272236" "8061"
    ),
    "SECP256K1": int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    ),
    "SECP256R1": int(
        "11579208921035624876269744694940757352999695522413576034242225906"
        "1068512044369"
    ),
    "SECP384R1": int(
        "39402006196394479212279040100143613805079739270465446667946905279"
        "627659399113263569398956308152294913554433653942643"
    ),
    "SECP521R1": int(
        "68647976601306097149819007990813932172694353001433054093944634591"
        "85543183397655394245057746333217197532963996371363321113864768612"
        "440380340372808892707005449"
    ),
}


def inverse_mod(a_num, m_mod):
    # a_num^-1 mod m_mod, m_mod must be prime
    # If not used on a prime modulo,
    #  can throw ZeroDivisionError.
    if a_num < 0 or m_mod <= a_num:
        a_num = a_num % m_mod
    i, j = a_num, m_mod
    x_a, x_b = 1, 0
    while i != 1:
        quot, rem = divmod(j, i)
        x_rem = x_b - quot * x_a
        j, i, x_b, x_a = i, rem, x_a, x_rem
    return x_a % m_mod


def sha2(raw_message):
    # SHA-2 256
    return hashlib.sha256(raw_message).digest()


def bytes_to_int(bytes_data):
    return int.from_bytes(bytes_data, "big")


def sha2_int(data):
    return bytes_to_int(sha2(data))


def curve_size(curve_name):
    # return the curve size (log2 N) from its name string
    try:
        curve_obj = getattr(ec, curve_name.upper())()
    except Exception as exc:
        raise Exception(
            f"Unknown curves. Curves names available : {list(CURVES_ORDER.keys())}"
        ) from exc
    return curve_obj.key_size


def curve_n(curve_name):
    # return the curve order "N" from its name string
    order = CURVES_ORDER.get(curve_name.upper())
    if not order:
        raise Exception(
            f"Unknown curves. Curves names available : {list(CURVES_ORDER.keys())}"
        )
    return order


def check_publickey(pubkey, curve_str):
    # Check pubkey (x,y) belongs on the curve
    try:
        curve_obj = getattr(ec, curve_str.upper())()
    except Exception as exc:
        raise Exception(
            f"Unknown curves. Curves names available : {list(CURVES_ORDER.keys())}"
        ) from exc
    if len(pubkey) != 2:
        raise Exception(
            'Public key data shall be provided as :\n "public_key" : [ x, y ]'
        )
    publickey_obj = ec.EllipticCurvePublicNumbers(pubkey[0], pubkey[1], curve_obj)
    ret = False
    try:
        publickey_obj.public_key(backends.default_backend())
        ret = True
    except ValueError:
        pass
    return ret


def privkey_to_pubkey(pv_key_int, curve_name):
    # Return public point coordinates (Scalar multiplication of pvkey with base point G)
    ec_backend = getattr(ec, curve_name.upper())()
    pubkey = (
        ec.derive_private_key(pv_key_int, ec_backend, backends.default_backend())
        .public_key()
        .public_numbers()
    )
    return [pubkey.x, pubkey.y]


def ecdsa_sign_kout(z_hash, pvkey, curve_name):
    # Perform ECDSA, but insecurely return the private k nonce
    n_mod = curve_n(curve_name)
    k_nonce = secrets.randbelow(n_mod)
    r_sig = scalar_mult_x(k_nonce, curve_name)
    s_sig = inverse_mod(k_nonce, n_mod) * (z_hash + r_sig * pvkey) % n_mod
    return r_sig, s_sig, k_nonce


def scalar_mult_x(d_scalar, curve):
    # Scalar multiplication of d with base point G
    # and return x, like ECDH with G.
    return privkey_to_pubkey(d_scalar, curve)[0]
