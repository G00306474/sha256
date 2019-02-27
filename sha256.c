//Kevin Moran 2019
//The Secure Hash Algorithm, 256 bit version
//https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

#include <stdio.h>
#include <stdint.h>

void sha256();

//see section 4.1.2 & 4.1.3 for defentions 
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);

//See section 3.2 for definitions
uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);

int main(int argc, char *argv[]){

  sha256();

  return 0;
}

void sha256(){
  
  //Message schedule (Section 6.2)
  uint32_t w [64];
  //Working Variables (Section 6.2)
  uint32_t a, b, c, d, e, f, g, h;
  //Two Temp Variables (Section 6.2)
  uint32_t T1, T2;

  //The hash value
  // The Values come from section 5.3.3
  uint32_t H[8]={
      0x6a09e667
    , 0xbb67ae85
    , 0x3c6ef372
    , 0xa54ff53a
    , 0x510e527f
    , 0x9b05688c
    , 0x1f83d9ab
    , 0x5be0cd19
  };

  //Current Message Block
  uint32_t M[16];
  //from page 22, W[t] = M[t] for 0 <= t <=15.
  for (int t =0; t<16; t++)
    W[t] = M[t];

  //From page 22, W[t] = .....
  for (t = 16; t < 64; t++)
    sigl(W[t-2])+ W[t-7] + sig0(W[t-15]) + W[t-16];


}
uint32_t sig0(uint32_t x){
  //See Section 3.2 & 4.1.2 for definitions
  return (rotr(7,x) ^ rotr(18, x) ^ shr(3,x));


}
uint32_t sig1(uint32_t x){
  //See Section 3.2 & 4.1.2 for definitions
  return (rotr(17,x) ^ rotr(19,x) ^ shr(10,x));
}

//see section 4.1.2 & 4.1.3 for defentions 
uint32_t rotr(uint32_t n, uint32_t x){
  return(x >> n) | (x << (32 - n));
}
uint32_t shr(uint32_t n, uint32_t x);{
  return(x >> n);
}


