<img src="docs/logo.svg" width="150" align="right"/>

# 🕴️Dress‑Up

Dress‑Up provides a parser-only implementation of the [SUIT][suit-rfc] manifest format,
for `no_std` environments. It relies on [minicbor] for CBOR parsing.
Dress‑Up parses CBOR on the fly during manifest execution and is zero-copy.

Dress‑Up is OS-agnostic, it provides an `OperatingHooks` trait
that allow an operating system to provide integration into the manifest processing.
While Dress‑Up is developed under the Ariel OS banner, it is not tied to Ariel OS.

The full manifest must be in memory during parsing.
The authentication object covers the inner manifest.
Both must be in memory for the authentication process.
The other reason is that Dress‑Up is zero-copy.
All text and byte strings are references into the CBOR data.

Dress-up only supports sequential processing of components.
Each component described in a manifest processes serially.
This saves the amount of memory required during the manifest
processing.

## Supported RFC features

Dress‑Up supports the following features from the SUIT manifest specification:

- Multiple components

Dress‑Up does not yet support the following features:

- Severable elements
- Reporting policy

Dress‑Up will never support the following features. These are out of scope:

- Parallel processing
- Manifest creation

### SUIT command support

Dress‑Up strives to support all commands of the SUIT specification.
The commands from the table below are currently supported.

| Command               |    |
|:----------------------|----|
| Vendor Identifier     | ✅ |
| Class Identifier      | ✅ |
| Image Match           | ✅ |
| Component Slot        | ✅ |
| Check Content         | ✅ |
| Set Component Index   | ✅ |
| Abort                 | ✅ |
| Try Each              | ✅ |
| Write Content         | ✅ |
| Override Parameters   | ✅ |
| Fetch                 | ✅ |
| Copy                  | 🚧 |
| Invoke                | 🚧 |
| Device Identifier     | ✅ |
| Swap                  | 🚧 |
| Run Sequence          | 🚧 |
| Custom commands       | 🚧 |

### Parameter support

Dress‑Up supports the following parameters

| Parameter             |    |
|:----------------------|----|
| Vendor ID             | ✅ |
| Class ID              | ✅ |
| Image Digest          | ✅ |
| Component Slot        | ✅ |
| Strict Order          | ❌ |
| Soft Failure          | 🚧 |
| Image Size            | ✅ |
| Content               | ✅ |
| URI                   | ✅ |
| Source Component      | 🚧 |
| Invoke Args           | 🚧 |
| Device ID             | ✅ |

## Overview

This section gives a brief overview of the primary types in this crate.

- [`SuitManifest`]: This starts the SUIT manifest parsing. Contains the functions required to
  check manifest validity. The [`Envelope`] structure derives from this.
- [`Envelope`]: Describes the SUIT Envelope structure. The Envelope contains both the
  authentication object and the manifest itself.
- [`manifest::Manifest`]: Contains the inner SUIT manifest. It provides access to the command
  sequences in the manifest.
- [`OperatingHooks`]: This trait provides the interface to the operating system functions
  required by Dress‑Up. The operating system or application running Dress‑Up must provide an
  implementation.

## Workflow

A typical flow with Dress‑Up consists of multiple steps:

1. Start the parsing by creating a [`SuitManifest`].
2. Authenticate the manifest via [`SuitManifest::authenticate`].
3. Derive the [`Envelope`] from the [`SuitManifest`] via [`SuitManifest::envelope`].
4. Deriver the inner [`Manifest`] from the [`Envelope`] via [`Envelope::manifest`].
5. check the existence of different command sequences and execute them when available.

## Example

```Rust
use cbor_edn::StandaloneItem;
use dress_up::SuitManifest;
# use minicbor::bytes::ByteSlice;
# use dress_up::error::Error;
# fn authenticate(_cose: &[u8], _auth: &[u8]) -> Result<bool, Error> {
#    Ok(true)
# }

let input = &r#"
107({
        / authentication-wrapper / 2:<< [
            / digest: / << [
                / algorithm-id / -16 / "sha256" /,
                / digest-bytes /
h'1f2e7acca0dc2786f2fe4eb947f50873a6a3cfaa98866c5b02e621f42074daf2'
            ] >>,
            / signature: / << 18([
                / protected / << {
                    / alg / 1:-7 / "ES256" /
                } >>,
                / unprotected / {
                },
                / payload / null / nil /,
                / signature / h'27a3d7986eddcc1bee04e1436746408c308ed3
c15ac590a1ca0cf96f85671ccac216cb9a1497fc59e21c15f33c95cf75203e25c287b3
1a57d6cd2ef950b27a7a'
            ]) >>
        ] >>,
        / manifest / 3:<< {
            / manifest-version / 1:1,
            / manifest-sequence-number / 2:1,
            / common / 3:<< {
                / components / 2:[
                    [h'00']
                ],
                / shared-sequence / 4:<< [
                    / directive-override-parameters / 20,{
                        / vendor-id /
1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
be9d-e663e4d41ffe /,
                        / class-id /
2:h'1492af1425695e48bf429b2d51f2ab45' /
1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14:34768
                    },
                    / condition-vendor-identifier / 1,15,
                    / condition-class-identifier / 2,15
                ] >>
            } >>,
            / validate / 7:<< [
                / condition-image-match / 3,15
            ] >>,
            / install / 20:<< [
                / directive-override-parameters / 20,{
                    / uri / 21:"http://example.com/file.bin"
                },
                / directive-fetch / 21,2,
                / condition-image-match / 3,15
            ] >>
        } >>
    })
"#;

let cbor = StandaloneItem::parse(input).unwrap().to_cbor().unwrap();
let suit = SuitManifest::from_bytes(&cbor);
let suit = suit.authenticate(|cose, payload| { authenticate(cose, payload) })?;
let envelope = suit.envelope()?;
let manifest = envelope.manifest()?;

assert_eq!(manifest.version()?, 1);
assert_eq!(manifest.sequence_number()?, 1);
# Ok::<(), Error>(())
```
[suit-rfc]: https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34
[minicbor]: https://crates.io/crates/minicbor
