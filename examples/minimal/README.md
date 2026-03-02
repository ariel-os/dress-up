# SUIT minimal example

This example acts as minimal demonstrator, showing how to use dress-up to
update a memory region inside a simple application.

## Usage

Run the example with:

```console
cargo run -- suit.cbor payload.bin public.pem
```

## Details

The application requires the suit manifest, the payload and the public key
supplied as files via the application arguments.

As the payload is supplied via the arguments, actual payload fetch is happening
via a network connection. Instead, the application uses the supplied payload
when it is instructed to fetch a payload by the manifest.

### Keypair

The public key must be a PEM-encoded plain ecdsa public key.
A keypair can be generated with openssl:

```console
openssl ecparam -name secp256k1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

## Generating the SUIT Manifest

The [suit-tool] from ARM can be used to generate the keys and suit manifest.


[suit-tool]: https://gitlab.arm.com/research/ietf-suit/suit-tool
