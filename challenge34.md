# MITM Key-fixing attack on DH with parameter injection

This attack works by replacing Alice and Bob's public keys with *p* during the handshake.

 1. Alice and Bob publicly agree to use a modulus *p* = 23 and base *g* = 5 (which is a primitive root modulo 23).
 2. Mike is MITM'ing the connection between Alice and Bob.
 3. Alice sends Mike *p*, *g*, and *A*.
    - *A* = 5<sup>4</sup> mod 23 = 4
 4. Mike replaces *A* with *p* and forwards the message to Bob.
 5. Bob sends Mike *p*, *g*, and *B*.
    - *B* = 5<sup>3</sup> mod 23 = 10
 6. Mike replaces *B* with *p* and sends it to Alice.
 7. Alice computes *s* = *p*<sup>*a*</sup> mod *p*
    - s = 23<sup>4</sup> mod 23 = 0
 8. Bob computes *s* = *p*<sup>*b*</sup> mod *p*
    - s = 23<sup>3</sup> mod 23 = 0

Since the public keys are the same as the prime, the generated number will always be 0.