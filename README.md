# Lattice ECDSA Attack

Recover an ECDSA private key from partial "k" nonces data.

The partial "k" information can be recovered from side channels : timing gives its size (leading 0), modular operations can give parity, ...

This software requires at least 4 known bits per nonce : LSB (last bits known) or MSB (first bits known). It computes what is the minimum amount of signatures data required to recover the key, before performing the recovery.

It uses linear matrices and [lattice basis reduction to solve a Shortest Vector Problem](https://en.wikipedia.org/wiki/Lattice_problem) from a Hidden Number Problem.


## Requirements

* Python3
* cryptography library
* fpylll library

cryptography : `pip3 install cryptography` or `apt install python3-cryptography`

fpylll : doesn't work in Windows, only in Linux.  
          -> `apt install python3-fpylll`

We recommend that you **install fpylll with the distribution package manager**. Else this requires lots of compilation tools and Python low level libraries. The package managers, such as apt or dnf, are providing all these, with pre-compiled binaries.


## Use

Read a JSON data file with the signatures, with the following keys :  
* The name of the curve, see CURVES_ORDER in ecdsa_lib.py  
* Target public key is given as list of the coordinates : [x,y]
* Message given as bytes integers list
* The type of bits known : "LSB" or "MSB"
* The number of known bits per secret k
* The signatures as a list of dictionaries, with integers values : {"r": intR, "s": intS, "kp": knownNoncePart }

```
{
    "curve": curveString,
    "public_key": [pubx, puby],
    "message": [a,b,c,...], // In case same message for all signatures
    "known_type": "LSB"/"MSB",
    "known_bits": 6
    "signatures": [ {"r": intR, "s": intS, "kp": leakednoncepart }, {...}, ... ]
}
```

2^known_bits is a upper bound for kp.  
Example if the LSB known for "k" are 0b000101 for a given signature  
 -> { "hash": xyz, "r": xxx, "s": xxx, "kp": 5 }  

"hash" needs to be provided as integer in the signatures data when there's no "message" key. That means each signature has its own hash.

MSB shall be provided reduced like LSB, means only the known bits :  
0b000101... -> "kp": 5  
If the known bits are all 0 : "kp": 0

Run :

```
python3 lattice_attack.py [-f data.json]
```

There's a demo mode, provided by `gen_data.py`. Before performing an attack, it generates a random EC key pair (private/public), signs many messages with this key, and builds the data file accordingly ("data.json" by default).

Call lattice_attack and gen_data with the "-h" argument to see more about the options.


## Bibliography

These related publications helped to develop this software. You can also find out deeper insights about the underlying mathematics used.

**Hardness of Computing the Most Significant Bits of Secret Keys in Diffie-Hellman and Related Schemes**  
by Dan Boneh and Ramarathnam Venkatesan  
CRYPTO '96: Proceedings of the 16th Annual International Cryptology Conference on Advances in Cryptology, August 1996  
[PDF Link](https://link.springer.com/content/pdf/10.1007%2F3-540-68697-5_11.pdf)

**Return of the Hidden Number Problem**  
A Widespread and Novel Key Extraction Attack on ECDSA and DSA  
by Kegan Ryan  
IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES), December 2018  
[PDF Link](https://tches.iacr.org/index.php/TCHES/article/view/7337/6509)

**Minerva : The curse of ECDSA nonces**  
Systematic analysis of lattice attacks on noisy leakage of bit-length of ECDSA nonces  
by Ján Jančár, Vladimír Sedláček1, Petr Švenda and Marek Sýs  
Cryptographic Hardware and Embedded Security (CHES 2020), September 2020  
[PDF Link](https://eprint.iacr.org/2020/728.pdf)

**Biased Nonce Sense : Lattice Attacks Against Weak ECDSA Signatures in Cryptocurrencies**  
by Joachim Breitner and Nadia Heninger  
Financial Cryptography and Data Security 23rd International Conference, January 2019  
[PDF Link](https://fc19.ifca.ai/preproceedings/104-preproceedings.pdf)

**A Side Journey to Titan**  
Side-Channel Attack on the Google Titan Security Key  
by Victor Lomne and Thomas Roche  
January 2021  
[PDF Link](https://ninjalab.io/wp-content/uploads/2021/01/a_side_journey_to_titan.pdf)


## License

Copyright (C) 2021  Antoine FERRON - BitLogiK

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
