#!/usr/bin/env python3

# Extract data from real traces for Lattice ECDSA Attack
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
# Compute data input from the power analysis study :
# Return of ECC dummy point additions
#  Simple Power Analysis on efficient P-256 implementation
#
# by Andy Russon
# Paper :
# https://www.sstic.org/media/SSTIC2021/SSTIC-actes/return_of_ecc_dummy_point_additions_simple_power_a/SSTIC2021-Article-return_of_ecc_dummy_point_additions_simple_power_analysis_on_efficient_p-256_implementation-russon.pdf
#
# Get raw data traces online and generate LatticeAttack compatible json input file


import argparse
import base64
import functools
import json
import hashlib
import os
import tarfile
import urllib.request


# Original data set for traces get from :

RESOURCE_URL = (
    "https://github.com/orangecertcc/ecdummyrpa/raw/"
    "144974ae1c35eb1f0ef0f0fdbb4299d808624f7a/sample.tar.gz"
)


# Helpers from ecdsa_lib
def sha2(raw_message):
    # SHA-2 256
    return hashlib.sha256(raw_message).digest()


def sha2_int(data):
    return int.from_bytes(sha2(data), "big")


# Special helpers for this case


def sigDER_to_ints(sigDER):
    lenr = int(sigDER[3])
    lens = int(sigDER[5 + lenr])
    r = int.from_bytes(sigDER[4 : lenr + 4], "big")
    s = int.from_bytes(sigDER[lenr + 6 : lenr + 6 + lens], "big")
    return r, s


def pubkeyPEM_to_X962(PEMstring):
    PEMparts = PEMstring.split("-----")
    pubkey_b64 = PEMparts[2].strip("\r\n")
    # end of DER is X962 public key
    return base64.b64decode(pubkey_b64)[-65:]


def pubkeyX962_to_intpair(DERpubk):
    x_int = int.from_bytes(DERpubk[1:33], "big")
    y_int = int.from_bytes(DERpubk[33:], "big")
    return [x_int, y_int]


def pubkeyPEM_to_xy(PEMstr):
    return pubkeyX962_to_intpair(pubkeyPEM_to_X962(PEMstr))


def load_traces():
    # Reads traces from this RPA campain
    # Prepare to an almost compliant with LatticeAttack
    # But it requires then filtering to compute "kp" from "trace"
    files = os.listdir("test")
    nsig = len(files) // 3
    print(f"{len(files)} files detected for {nsig} signatures")
    traces = []
    for i in range(nsig):
        with open(f"test/trace_{i}.txt", "r") as tracef:
            data_trace = [float(line) for line in tracef]
        with open(f"test/signature_{i}.bin", "rb") as sigf:
            DERsig = sigf.read()
        with open(f"test/message_{i}.txt", "rb") as msgf:
            msg = msgf.read()
        trace_data = {}
        sig_ints = sigDER_to_ints(DERsig)
        trace_data["hash"] = sha2_int(msg)
        trace_data["r"] = sig_ints[0]
        trace_data["s"] = sig_ints[1]
        trace_data["trace"] = data_trace
        traces.append(trace_data)
    return traces


KNOWN_BITS = 7


def mean_compute(table_array):
    # compute arithmetic mean value to get the height of the valley
    return functools.reduce(lambda i, j: i + j, table_array) / len(table_array)


def select_sig(sig_candidate):
    # Filtering the good signatures
    # mean value < limit
    # "A valley considerably lower than the others indicating a nonce that has
    #    its 7 least significant bits set to 0."
    LIMIT = 20
    DISCARD_SIZE = 0.25  # Discard first and last 25% = keeps "half" middle
    trace_len = len(sig_candidate["trace"])
    start_idx = int(trace_len * DISCARD_SIZE)
    trace_interest = sig_candidate["trace"][start_idx : trace_len - start_idx]
    val = mean_compute(trace_interest)
    return val < LIMIT


def compute_kp(onesig):
    # Generate final data objects (with kp)
    sigout = {}
    sigout["hash"] = onesig["hash"]
    sigout["r"] = onesig["r"]
    sigout["s"] = onesig["s"]
    sigout["kp"] = 0
    return sigout


def get_data_source(res_url):
    # Get tar gz file at given url and extract files locally
    # Use this only on known trusted or friendly TAR files,
    # as this can write files anywhere locally
    with urllib.request.urlopen(res_url) as remote_data:
        tardata = tarfile.open(fileobj=remote_data, mode="r:gz")
        print("Extracting data files ...")
        tardata.extractall()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Load ecdummyRPA traces mesurements for ECDSA attack file format."
    )
    parser.add_argument(
        "-f",
        default="data.json",
        help="File name output",
        metavar="fileout",
    )
    arg = parser.parse_args()

    # Test id data were downloaded by testing presence of pubkey file
    if not os.path.exists("pubkey.pem"):
        print("Downloading raw data ...")
        get_data_source(RESOURCE_URL)

    print("Loading files ...")
    sigs_data = load_traces()
    print("Filtering signatures traces")
    sigs_data_selected = [compute_kp(asig) for asig in sigs_data if select_sig(asig)]
    with open("pubkey.pem", "r") as pkf:
        pubkey_pem = pkf.read()
    global_data = {
        "curve": "SECP256R1",
        "public_key": pubkeyPEM_to_xy(pubkey_pem),
        "known_type": "LSB",
        "known_bits": KNOWN_BITS,
        "signatures": sigs_data_selected,
    }
    with open(arg.f, "w") as fout:
        json.dump(global_data, fout)
    print(f"File {arg.f} written with all data.")
