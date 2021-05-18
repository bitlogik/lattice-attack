#!/usr/bin/env python3

# Lattice ECDSA Attack - Setup file
# Copyright (C) 2021  Antoine Ferron - BitLogiK

from setuptools import setup

with open("README.md") as readme_file:
    readme = readme_file.read()


requirements = [
    "cryptography>=3.4.1",
    "fpylll>=0.5",
]


setup(
    name="lattice-attack",
    version="0.1.0",
    description="Lattice ECDSA Attack from partial nonces.",
    long_description=readme + "\n\n",
    author="BitLogiK",
    author_email="contact@bitlogik.fr",
    url="https://github.com/bitlogik/lattice-attack",
    python_requires=">=3.6",
    install_requires=requirements,
    license="GPLv3",
    keywords="cryptography",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security :: Cryptography",
    ],
    long_description_content_type="text/markdown",
)
