MFOC is an open source implementation of "offline nested" attack by Nethemba.

This program allow to recover authentication keys from MIFARE Classic card.

Please note MFOC is able to recover keys from target only if it have a known key: default one (hardcoded in MFOC) or custom one (user provided using command line).

# Build from source

```
autoreconf -is
./configure
make && sudo make install
```

# Usage #
Put one MIFARE Classic tag that you want keys recovering;
Lauching mfoc, you will need to pass options, see
```
mfoc -h
```
