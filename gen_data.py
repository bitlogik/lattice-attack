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


def generates_signatures(number_sigs, message, kbits, data_type, curve):
    print("Preparing Data")
    d_key = random.randrange(ecdsa_lib.curve_n(curve))
    print("Private key to be found (as demo) :")
    print(hex(d_key))
    sigs = []
    sz_curve = ecdsa_lib.curve_size(curve)
    kbi = int(2 ** kbits)
    print(f"Generating {number_sigs} signatures with curve {curve.upper()}")
    print(f" leaking {kbits} bits for k ({data_type})  ...")
    if message is not None:
        msg = message.encode("utf8")
        # Always hash message provided with SHA2-256, whatever
        hash_int = ecdsa_lib.sha2_int(msg)
    for _ in range(number_sigs):
        if message is None:
            # Use a random different message for each signature
            # Note : there is no associated message from the hash
            #  Do not ever that in practice, this is insecure, only here for demo
            hash_int = random.randrange(ecdsa_lib.curve_n(curve))
        # Compute signatures with k (nonce), r, s
        sig_info = ecdsa_lib.ecdsa_sign_kout(hash_int, d_key, curve)
        # pack and save data as : r, s, k%(2^bits) (partial k : "kp")
        sigs.append(
            {
                "r": sig_info[0],
                "s": sig_info[1],
                "kp": sig_info[2] % kbi
                if data_type == "LSB"
                else sig_info[2] >> (sz_curve - kbits),
            }
        )
        if message is None:
            sigs[-1]["hash"] = hash_int
    ret = {
        "curve": curve.upper(),
        "public_key": ecdsa_lib.privkey_to_pubkey(d_key, curve),
        "known_type": data_type,
        "known_bits": kbits,
        "signatures": sigs,
    }
    if message is not None:
        ret["message"] = list(msg)
    return ret


if __name__ == "__main__":
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
