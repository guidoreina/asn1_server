# `asn1_ber_server`
`asn1_ber_server` is a TCP server written in C++ which listens on one or more ports and saves the received ASN.1 records on disk.

## Usage:
```
Usage: ./asn1_ber_server [--bind <ip-port>]+ [--number-workers <number-workers>] --temp-dir <directory> --final-dir <directory> --max-file-size <size> --max-file-age <seconds>
<ip-port> ::= <ip-address>:<port>
<ip-address> ::= <ipv4-address> | <ipv6-address>

Number of workers: 1 .. 32, default: 1.
File size: 1 .. 4194304.
File age: 1 .. 3600 (seconds).
```


# `berdecoder`
`berdecoder` is a ASN.1 BER decoder written in C++.

## Usage:
```
Usage: ./berdecoder <filename>
```
