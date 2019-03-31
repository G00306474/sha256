# SHA-256

#### What Is Sha-256
<hr/>

Secure Hash Algorithm 256 or SHA 256 is defined as one of the most secure ways to protect digital information. 
SHA 256 is a math process that generates a 256 bit (64 character long) random sequence of letters and numbers 
(hash) out of any input.

A hash is not ‘encryption’ – it cannot be decrypted back to the original text (it is a ‘one-way’ cryptographic function, and 
is a fixed size for any size of source text). This makes it suitable when it is appropriate to compare ‘hashed’ versions of texts,
as opposed to decrypting the text to obtain the original version.


##### How It Works
Functions Used 

Ch(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) : The x input chooses if the output is from y or from z. More precisely, for each bit index, that result bit is according to the bit from y (or respectively z ) at this index, depending on if the bit from x at this index is 1 (or respectively 0).

Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z) : for each bit index, that result bit is according to the majority of the 3 inputs bits for x y and z at this index.

SIG0(X) = RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22),

SIG1(X) = RotR(X, 6) ⊕ RotR(X, 11) ⊕ RotR(X, 25),

sig0(X) = RotR(X, 7) ⊕ RotR(X, 18) ⊕ ShR(X, 3),

sig1(X) = RotR(X, 17) ⊕ RotR(X, 19) ⊕ ShR(X, 10).

and the 64 binary words Ki given by the 32 first bits of the fractional parts of the cube roots of the first
64 prime numbers:
0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2


Padding
SHA 256 works by reading blocks in sizes of 512 with the final 64 bits of the last block used to state the size of the original message. 
 Suppose a message has length L < 2^64.  Before it is input to the
 hash function, the message is padded on the right as follows:

    a.  "1" is appended.  Example: if the original message is
        "01010000", this is padded to "010100001".

    b.  K "0"s are appended where K is the smallest, non-negative
        solution to the equation

             L + 1 + K = 448 (mod 512)

    c.  Then append the 64-bit block that is L in binary representation.
        After appending this block, the length of the message will be a
        multiple of 512 bits.

        Example:  Suppose the original message is the bit string

             01100001 01100010 01100011 01100100 01100101

        After step (a), this gives

             01100001 01100010 01100011 01100100 01100101 1

        Since L = 40, the number of bits in the above is 41 and K = 407
        "0"s are appended, making the total now 448.  This gives the
        following in hex:

             61626364 65800000 00000000 00000000
             00000000 00000000 00000000 00000000
             00000000 00000000 00000000 00000000
             00000000 00000000

        The 64-bit representation of L = 40 is hex 00000000 00000028.
        Hence the final padded message is the following hex:

             61626364 65800000 00000000 00000000
             00000000 00000000 00000000 00000000
             00000000 00000000 00000000 00000000
             00000000 00000000 00000000 00000028
[Source](https://tools.ietf.org/html/rfc4634#page-6)

Hash computation
First, eight variables are set to their initial values, given by the first 32 bits of the fractional part
of the square roots of the first 8 prime numbers:
H1(0)= 0x6a09e667 
H2(0) = 0xbb67ae85 
H3(0)= 0x3c6ef372
H4(0)= 0xa54ff53a
H5(0)= 0x510e527f  
H6(0)= 0x9b05688c 
H7(0) = 0x1f83d9ab 
H8(0)= 0x5be0cd19
Next the message blocks are passed one at a time. 
construct the 64 blocks Wi from M(t)

– set
(a, b, c, d, e, f, g, h) = (H1(t−1), H2(t−1), H3(t−1), H4(t−1), H5(t−1), , H6(t−1), H7(t−1), H8(t−1))
– do 64 rounds consisting of:
T1 = h + Σ1(e) + Ch(e, f, g) + Ki + Wi
T2 = Σ0(a) + M aj(a, b, c)
h = g
g = f
f = e
e = d + T1
d = c
c = b
b = a
a = T1 + T2
Then compute the values of the new H
H1(t) = H1(t-1)+a
H2(t) = H2(t-1)+b
H3(t) = H3(t-1)+c
H4(t) = H4(t-1)+d
H5(t) = H5(t-1)+e
H6(t) = H6(t-1)+f
H7(t) = H7(t-1)+g
H8(t) = H8(t-1)+h

The hash of the message is the concatenation of the variables H after the last block has been
processed


##### Running The Code
Download the file called sha256.c
Compile the program using the command. ( gcc -o sha256 sha256.c )
Run the program using the command. ( ./sha256 NameofFile example (./sha256 testFile ))
If the file exists in the directory it will return the hash value
If the file doesnt exist in the current directory it will return that the file doesnt exist. All you need to do then is move the fiel you want to use into the same folder as the Sha256.c file. 


##### Problem With Code
This code will not fully funtion if ran on a little endian system. If run on a little endian system the hash value will be in little endian and the standard states that it needs to be in big endian. So it needs to run on a big endian system or needs a function to test the endianess of the system and alter the message block if needed. To test if a linux system is big endian or little endian you just need to run  " echo I | tr -d [:space:] | od -to2 | head -n1 | awk '{print $2}' | cut -c6"   in the command prompt. If you recieve a 1 it is little endian if you get a 0 it is big endian.

#### References
<hr/>

[Cryptographic-hash-function](https://komodoplatform.com/cryptographic-hash-function/)

[SHA-256 Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

[Explanation of Hash Functions](https://www.youtube.com/watch?v=mbekM2ErHfM)

[Linux how to tell if systme is Big Endian or Little Endian](https://serverfault.com/questions/163487/how-to-tell-if-a-linux-system-is-big-endian-or-little-endian)
