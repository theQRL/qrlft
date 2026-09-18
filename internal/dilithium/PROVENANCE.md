# Vendored Dilithium

This is `crypto/dilithium` from
[theQRL/go-qrllib](https://github.com/theQRL/go-qrllib) v0.8.0, copied here
unchanged apart from the import path. Both projects are MIT licensed by theQRL;
`LICENSE` in this directory is go-qrllib's, kept with the code it covers.

## Why it lives here

go-qrllib removed Dilithium at v0.9.0. qrlft still has to verify releases signed
before FIPS 204 was finalised, which is every QRL release up to and including
qrlft v4.0.2, so the implementation that produced those signatures has to stay
available somewhere. ML-DSA-87 continues to come from go-qrllib, which is where
the maintained, standards-tracked code belongs.

Splitting the two means qrlft can follow go-qrllib forward without carrying a
scheme go-qrllib has finished with, and without stranding signatures that are
still in the wild.

## Rules for this directory

It is under `internal/` on purpose: nothing outside qrlft can import it, so
vendoring a copy does not turn qrlft into a distributor of a Dilithium library.

Treat it as frozen. Dilithium is pre-standard and superseded, and the only
reason to touch this code is a defect that changes verification of signatures
already published, which would be a serious finding rather than a routine
change. Anything new gets signed with ML-DSA-87.

The upstream tests came with it and are expected to keep passing. They are the
evidence that the copy still behaves like the code that made those signatures.
