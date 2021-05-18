#!/usr/bin/env python3

# Random demo data generator for Lattice ECDSA Attack
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


import argparse
import random
import json

import ecdsa_lib


def generates_signatures(number_sigs, msg, kbits, data_type, curve):
    print("Preparing Data")
    d_key = random.randrange(ecdsa_lib.curve_n(curve))
    print("Private key to be found (as demo) :")
    print(hex(d_key))
    q_pub = ecdsa_lib.privkey_to_pubkey(d_key, curve)
    sigs = []
    kbi = int(2 ** kbits)
    print(f"Generating {number_sigs} signatures with curve {curve.upper()}")
    print(f" leaking {kbits} bits for k ({data_type})  ...")
    for _ in range(number_sigs):
        # Compute signatures with k (nonce), r, s
        sig_rx, sig_s, sig_k = ecdsa_lib.ecdsa_sign_kout(msg, d_key, curve)
        # pack and save data as : r, s, k%(2^bits) (partial k : "kp")
        sigs.append(
            {
                "r": sig_rx,
                "s": sig_s,
                "kp": sig_k % kbi if data_type == "LSB" else sig_k >> (256 - kbits),
            }
        )
    return {
        "curve": curve,
        "public_key": q_pub,
        "message": list(msg),
        "known_type": data_type,
        "known_bits": kbits,
        "signatures": sigs,
    }


if __name__ == "__main__":
    DEFAULT_MESSAGE = "Message Signed blah"
    parser = argparse.ArgumentParser(
        description="Generate random demo data for ECDSA attack."
    )
    parser.add_argument(
        "-f",
        default="data.json",
        help="File name output",
        metavar="fileout",
    )
    parser.add_argument(
        "-m",
        default=DEFAULT_MESSAGE.encode("utf8"),
        help="Message string",
        metavar="msg",
    )
    parser.add_argument(
        "-c", default="secp256k1", help="Elliptic curve name", metavar="curve"
    )
    parser.add_argument(
        "-b",
        default=6,
        type=int,
        help="Number of known bits (at least 4)",
        metavar="nbits",
    )
    parser.add_argument(
        "-t", default="LSB", help="bits type : MSB or LSB", metavar="type"
    )
    parser.add_argument(
        "-n",
        default=1000,
        type=int,
        help="Number of signatures to generate",
        metavar="num",
    )
    arg = parser.parse_args()
    sigs_data = generates_signatures(arg.n, arg.m, arg.b, arg.t, arg.c)
    with open(arg.f, "w") as fout:
        json.dump(sigs_data, fout)
    print(f"File {arg.f} written with all data.")
