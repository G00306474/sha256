//Kevin Moran 2019
//The Secure Hash Algorithm, 256 bit version
//https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

#include <stdio.h>
#include <stdint.h>

//Repersents a message block
union msgblock { 
  uint8_t e[64];
  uint32_t t[16];
  uint64_t s[8];
};

//A flag for reading the file
enum status {READ,PAD0,PAD1,FINISH};


//see section 4.1.2 & 4.1.3 for defentions 
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);

//See section 3.2 for definitions
uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);

//See section 4.1.2 for definition
uint32_t SIG0(uint32_t x);
uint32_t SIG1(uint32_t x);

uint32_t Ch(uint32_t x,uint32_t y, uint32_t z);
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

//Calculates the sha256 of a file
void sha256(FILE *fi);

//Retrieves the nest message block
int nextmsgblock(FILE *fi, union msgblock *M, enum status *S, uint64_t  *nobits);

//Start of program, calls sha256 and passes the file to it.
int main(int argc, char *argv[]){
    
  //Open file given as first command line argument.
  FILE* fi;
  fi  = fopen(argv[1], "r");
  //Add Error Checking HERE!!!  

  //Run the secure hash algo on the file. 
  sha256(fi);

  //Close the file 
  fclose(fi);
  return 0;
}

void sha256(FILE *fi){
  
  //Current Message block
  union msgblock M;
  
  //Number of bits read from the file 
  uint64_t nobits = 0;
  
  //The status of the message blocks, in terms of padding 
  enum status S = READ;

  //The K Constants. Defined in Section 4.2.2
  uint32_t K[]={
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 
  };


  //Message schedule (Section 6.2)
  uint32_t W[64];
  //Working Variables (Section 6.2)
  uint32_t a, b, c, d, e, f, g, h;
  //Two Temp Variables (Section 6.2)
  uint32_t T1, T2;

  //The hash value
  // The Values come from section 5.3.3
  uint32_t H[8]={
      0x6a09e667    , 0xbb67ae85
    , 0x3c6ef372    , 0xa54ff53a
    , 0x510e527f    , 0x9b05688c
    , 0x1f83d9ab    , 0x5be0cd19
  };


  int i,t;
  // Loop Through the message block as per page 22.
  while (nextmsgblock(fi, &M, &S, &nobits)){

  for (t =0; t<16; t++)

   W[t] = M.t[t];

  //From page 22, W[t] = .....
  for (t = 16; t < 64; t++)
   W[t] = sig1(W[t-2])+ W[t-7] + sig0(W[t-15]) + W[t-16];

   // Initialise a,b, c, d and e as per Step 2, Section 6.2.2
   a = H[0]; b= H[1]; c = H[2]; d = H[3]; 
   e = H[4]; f= H[5]; g = H[6]; h= H[7];

   // Step 3.
   for (t =0; t < 64; t++){
    T1 = h + SIG1(e) + Ch(e,f,g) + K[t] + W[t];
    T2 = SIG0(a) + Maj(a,b,c);
    h = g;
    g = f;
    f =e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
    }

   //Step 4.
   H[0] = a + H[0];   H[1] = b + H[1];
   H[2] = c + H[2];   H[3] = d + H[3];
   H[4] = e + H[4];   H[5] = f + H[5];
   H[6] = g + H[6];   H[7] = h + H[7];
  }
  printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",H[0], H[1],H[2],H[3], H[4], H[5], H[6],  H[7]);
 }
uint32_t sig0(uint32_t x){
  //See Section 3.2 & for definitions
  return (rotr(7,x) ^ rotr(18, x) ^ shr(3,x));


}
uint32_t sig1(uint32_t x){
  //See Section 3.2 for definitions
  return (rotr(17,x) ^ rotr(19,x) ^ shr(10,x));
}

//see section 4.1.2 & 4.1.3 for defentions 
uint32_t rotr(uint32_t n, uint32_t x){
  return(x >> n) | (x << (32 - n));
}
uint32_t shr(uint32_t n, uint32_t x){
  return(x >> n);
}
 
//See section 4.1.2 for definition
uint32_t SIG0(uint32_t x){
  return (rotr(2,x) ^ rotr(13,x) ^ rotr(22,x));
}
uint32_t SIG1(uint32_t x){
  return (rotr(6,x) ^ rotr(11,x) ^ rotr(25,x));
}
 
uint32_t Ch(uint32_t x,uint32_t y, uint32_t z){
  return((x & y) ^ ((!x) & z));
}
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
  return((x & y) ^ (x & z) ^ (y & z));
}

int nextmsgblock(FILE *fi, union msgblock *M, enum status *S, uint64_t  *nobits){

  //Number of bytes from fread. 
  uint64_t nobytes;
    
  //For Looping
  int i;
  //If we have finished all the message blocks, then s should be finish.
  if (*S == FINISH)
      return 0;
  //Otherwise, check if we need another block full of padding. 
  if (*S == PAD0 || *S == PAD1){
    //Set first 56 bytes to all Zero bits.
    for (i = 0; i < 56; i++) {
        M->e[i] = 0x00;
      //Set the last 64 bits to the number of bits in the file (BE)
    }
    M->s[7] = *nobits;
    //Tells S we are finished.
    *S = FINISH;
    // If S was PAD1, set the first bit of M to 1. 
    if (*S == PAD1){
      M->e[0]= 0x80;
    }
    //Keep the loop in sha256 going for one more iteration.
    return 1;
  }
  // If we get here, we havent finished reading the file
  nobytes =  fread(M->e, 1, 64,fi);

  //Keep track of number of bytes read.
  *nobits = *nobits +  (nobytes * 8);
  //If we read less than 56 bytes we can put all padding in this block.
  if (nobytes < 56){
    //Add the one bit, as per the standard. 
    M->e[nobytes] = 0x80;
    //Add zero bits, till the last 64 bits. 
    while (nobytes < 56) {
      nobytes = nobytes + 1;
      M->e[nobytes] = 0x00;
    }
    //Append the file size in bits as a unsigned 64 bit int.
    M->s[7] = *nobits;
    *S  = FINISH;
  }
  //Otherwise check if we can put some padding into this block. 
   else if (nobytes < 64  ) {
      //Tell S we need another message block, with padding but no one bit.  
      *S = PAD0;
      //Put the one bit inot the current block.
      M->e[nobytes] = 0x80;
      // Pad the rest of the block with zero bits. 
      while (nobytes < 64) {
        nobytes = nobytes + 1;
        M->e[nobytes] = 0x00; 
      }
    }
    //Otherwise check if we're at the end of the file. 
    else if (feof(fi)){
    //Tell S we need another message block with just the padding 
     *S = PAD1;
    } 
    
  // if we get this far, then we will return one to call this function again. 
   return 1;
}

