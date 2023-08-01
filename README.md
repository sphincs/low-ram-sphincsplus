This repository contains an implementation of Sphincs+ which is designed to be HSM friendly.
In particular, it minimizes the amount of RAM used.  On my computer, it can generate or verify
a Sphincs+ signature (1SHA2-28F-SIMPLE) with just 1k of RAM.

It achieves this low RAM uses (far smaller than the actual size of the signature) by streaming
the signature; it can generate the signature (or read the signature on verify) in pieces (possibly
even as small as 1 byte at a time), and so we don't need the RAM to hold the entire signature.

See the read.me for more details
