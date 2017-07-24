# aes-cpa
This repository includes the software artifacts used for our paper:
> Alex Biryukov, Daniel Dinu, and Yann Le Corre,
> [Side-Channel Attacks meet Secure Network Protocols][paper],
> ACNS 2017

## Description
Features:
* symbolic processing of an initial state
* CPA attack on a given evaluation case

The source code can be used to attack two implementations of the AES:
* S-box implementation
* T-table implementation
 
For details, read [our paper][paper] or have a look at the source code.

## Required Packages
* matplotlib
* numpy

## Acknowledgement
This work is supported by the CORE project ACRYPT (ID C12-15-4009992) funded by 
the [Fonds National de la Recherche, Luxembourg][fnr].

[paper]: http://orbilu.uni.lu/bitstream/10993/31797/1/ACNS2017.pdf
[fnr]: https://www.fnr.lu/
