# Diffie-Hellman

From the [Diffie—Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) Wikipedia page:
> Diffie-Hellman key exchange is a method of securely exchanging cryptographic keys
> over a public channel and was one of the first public-key protocols as conceived by
> Ralph Merkle and named after Whitfield Diffie and Martin Hellman.

Diffie-Hellman establishes a shared secret between two parties that can be used
for secret communication for exchanging data over a public network.

## Algorithm Details

The original implementation of the protocol uses the multiplicative group of
integers modulo *p*, where *p* is prime, and *g* is a prime root modulo *p*.

 1. Alice and Bob publicly agree to use a modulus *p* = 23 and base *g* = 5 (which is a primitive root modulo 23).
 2. Alice chooses a secret integer *a* = 4, then sends it to Bob *A* = *g*<sup>*a*</sup> mod *p*.
    - *A* = 5<sup>4</sup> mod 23 = 4
 3. Bob chooses a secret integer *b* = 3, then sends Alice *B* = *g*<sup>*b*</sup> mod *p*
    - *B* = 5<sup>3</sup> mod 23 = 10
 4. Alice computes *s* = *B*<sup>*a*</sup> mod *p*
    - s = 10<sup>4</sup> mod 23 = 18
 5. Bob computes *s* = *A*<sup>*b*</sup> mod *p*
    - s = 4<sup>3</sup> mod 23 = 18
 6. Alice and Bob now share a secret (the number 18).

Alice and Bob have arrived at the same values because under mod p,

<!-- 
A^b mod p    = g^{ab} mod p
g^{ab} mod p = g^{ba} mod p
g^{ba} mod p = B^a mod p
-->
![formula](https://render.githubusercontent.com/render/math?math=A^b%5c%20mod%5c%20p=g^{ab}%5c%20mod%5c%20p=g^{ba}%5c%20mod%5c%20p=B^a%5c%20mod%5c%20p)