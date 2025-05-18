# CS 355 Programming Project: Ring Signature using SNARKs in Plonky2

Welcome to the CS 355 Programming Project! 

You only need to edit `./src/gadgets/rsa.rs` to complete this project. The file may look overwhelming at first but don't fret! You only need to edit a small portion of it. 

Please look for the `unimplemented!()` snippets for where to write your solution. Once complete, please remove/comment out the line so that your code compiles.

## Compiling and Running

Please refer to the Project spec for instructions on how to genreate an RSA keypair, compile the circuits, and generate and verify the SNARK proof. 

## Testing

Run all tests using
```bash
cargo test --release
```

or a specifc test e.g.,
```bash
cargo test --release test_compute_padded_hash
```

