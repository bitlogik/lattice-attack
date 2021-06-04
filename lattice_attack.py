#!/usr/bin/env python3

# Lattice ECDSA Attack
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
# Recover ECDSA private key from partial "k" nonce data
# Minimum 4 known bits per nonce : LSB or MSB
#
# Use linear matrices and lattice basis reduction to solve SVP from a
# Hidden Number Problem
#
#
# Install cryptography and fpylll
#  cryptography : pip3 install cryptography
#    or apt install python3-cryptography
#  fpylll : doesn't work in Windows
#           -> apt install python3-fpylll


import argparse
import json
import random

from fpylll import LLL, BKZ, IntegerMatrix
import ecdsa_lib


# DATA Format of the JSON file :
# {
#    "curve": curveString,
#    "public_key": publicKey,
#    "message": message, // In case same message for all sigs
#    "known_type": dataBitsType,
#    "known_bits": kbits,
#    "signatures": sigs,
# }
#
# curveString is the name of the curve, see CURVES_ORDER in ecdsa_lib
# publicKey is a list of the integer coordinates [Qx, Qy]
# message is the message bytes integers in a list
# dataBitsType is the type of bits known : "LSB" or "MSB"
# kbits is the number of known bits per secret k
# signatures is a list of signatures dictionaries, with parameters as integers
#  [ {"hash": xyz, "r": intR, "s": intS, "kp": leakednoncepart }, {...}, ... ]
#
# "hash" needs to be provided when no "message" key. Means each signature
# has its own hash.
#
# Example if the LSB known for "k" are 0b000101 for a sig
# -> { "r": xxx, "s": xxx, "kp": 5 }
# MSB shall be provided reduced like LSB, means only the known bits 0b000101... -> 5
#
# To convert to integer :
# if got bytes use : int.from_bytes(bytesvar, bytesorder="big")
# if got hex use : int(hexintvar, 16)
#
# To generate fake data for demo use gen_data.py


def reduce_lattice(lattice, block_size=None):
    if block_size is None:
        print("LLL reduction")
        return LLL.reduction(lattice)
    print(f"BKZ reduction : block size = {block_size}")
    return BKZ.reduction(
        lattice,
        BKZ.Param(
            block_size=block_size,
            strategies=BKZ.DEFAULT_STRATEGY,
            auto_abort=True,
        ),
    )


def test_result(mat, target_pubkey, curve):
    mod_n = ecdsa_lib.curve_n(curve)
    for row in mat:
        candidate = row[-2] % mod_n
        if candidate > 0:
            cand1 = candidate
            cand2 = mod_n - candidate
            if target_pubkey == ecdsa_lib.privkey_to_pubkey(cand1, curve):
                return cand1
            if target_pubkey == ecdsa_lib.privkey_to_pubkey(cand2, curve):
                return cand2
    return 0


def build_matrix(sigs, curve, num_bits, bits_type, hash_val):
    num_sigs = len(sigs)
    n_order = ecdsa_lib.curve_n(curve)
    curve_card = 2 ** ecdsa_lib.curve_size(curve)
    lattice = IntegerMatrix(num_sigs + 2, num_sigs + 2)
    kbi = 2 ** num_bits
    inv = ecdsa_lib.inverse_mod
    if hash_val is not None:
        hash_i = hash_val
    if bits_type == "LSB":
        for i in range(num_sigs):
            lattice[i, i] = 2 * kbi * n_order
            if hash_val is None:
                hash_i = sigs[i]["hash"]
            lattice[num_sigs, i] = (
                2
                * kbi
                * (
                    inv(kbi, n_order)
                    * (sigs[i]["r"] * inv(sigs[i]["s"], n_order))
                    % n_order
                )
            )
            lattice[num_sigs + 1, i] = (
                2
                * kbi
                * (
                    inv(kbi, n_order)
                    * (sigs[i]["kp"] - hash_i * inv(sigs[i]["s"], n_order))
                    % n_order
                )
                + n_order
            )
    else:
        # MSB
        for i in range(num_sigs):
            lattice[i, i] = 2 * kbi * n_order
            if hash_val is None:
                hash_i = sigs[i]["hash"]
            lattice[num_sigs, i] = (
                2 * kbi * ((sigs[i]["r"] * inv(sigs[i]["s"], n_order)) % n_order)
            )
            lattice[num_sigs + 1, i] = (
                2
                * kbi
                * (
                    sigs[i]["kp"] * (curve_card // kbi)
                    - hash_i * inv(sigs[i]["s"], n_order)
                )
                + n_order
            )
    lattice[num_sigs, num_sigs] = 1
    lattice[num_sigs + 1, num_sigs + 1] = n_order
    return lattice


MINIMUM_BITS = 4
RECOVERY_SEQUENCE = [None, 15, 25, 40, 50, 60]
SIGNATURES_NUMBER_MARGIN = 1.03


def minimum_sigs_required(num_bits, curve_name):
    curve_size = ecdsa_lib.curve_size(curve_name)
    return int(SIGNATURES_NUMBER_MARGIN * 4 / 3 * curve_size / num_bits)


def recover_private_key(
    signatures_data, h_int, pub_key, curve, bits_type, num_bits, loop
):

    # Is known bits > 4 ?
    # Change to 5 for 384 and 8 for 521 ?
    if num_bits < MINIMUM_BITS:
        print(
            "This script requires fixed known bits per signature, "
            f"and at least {MINIMUM_BITS}"
        )
        return False

    # Is there enough signatures ?
    n_sigs = minimum_sigs_required(num_bits, curve)
    if n_sigs > len(signatures_data):
        print("Not enough signatures")
        return False

    loop_var = True
    while loop_var:
        sigs_data = random.sample(signatures_data, n_sigs)

        print("Constructing matrix")
        lattice = build_matrix(sigs_data, curve, num_bits, bits_type, h_int)

        print("Solving matrix ...")
        for effort in RECOVERY_SEQUENCE:
            lattice = reduce_lattice(lattice, effort)
            res = test_result(lattice, pub_key, curve)
            if res:
                return res
        loop_var = loop
        if loop:
            print("One more try")

    return 0


def lattice_attack_cli(file_name, loop):
    print("\n ----- Lattice ECDSA Attack ----- ")
    print(f"Loading data from file {file_name}")
    try:
        with open(file_name, "r") as fdata:
            data = json.load(fdata)
    except FileNotFoundError:
        print(f"Data file '{file_name}' was not found.")
        return
    except IOError:
        print(f"Data file {file_name} can't be accessed.")
        return
    except json.JSONDecodeError:
        print("Data file content is not JSON compatible.")
        return
    message = data.get("message")
    if message:
        hash_int = ecdsa_lib.sha2_int(bytes(message))
    else:
        hash_int = None  # Signal to use a hash per sig, sig data
    curve_string = data["curve"]
    data_type = data["known_type"]
    known_bits = data["known_bits"]
    signatures = data["signatures"]
    q_target = data["public_key"]
    if not ecdsa_lib.check_publickey(q_target, curve_string):
        print(
            f"Public key data invalid, not on the given {curve_string.upper()} curve."
        )
        return
    print(f"Running with {known_bits} bits of k ({data_type})")
    print(f"Starting recovery attack (curve {curve_string.upper()})")
    if loop:
        print("Will shuffle loop until the key found.")
    result = recover_private_key(
        signatures, hash_int, q_target, curve_string, data_type, known_bits, loop
    )
    if result:
        print("Key found \\o/")
        print(hex(result))
    else:
        print("Private key not found. Sorry For Your Loss")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ECDSA attack from JSON data file.")
    parser.add_argument(
        "-f",
        default="data.json",
        help="File name intput",
        metavar="filein",
    )
    parser.add_argument("-l", help="Loop shuffle until found", action="store_true")
    arg = parser.parse_args()
    lattice_attack_cli(arg.f, arg.l)
    print("")
