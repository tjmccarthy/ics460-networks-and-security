/* Functions used in the tasks of the RSA Lab */
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

/* Derives the private key from the public key (e,n). */
BIGNUM* generatePrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e);

/* Uses RSA algorithm to encrypt a message using the public key provided. */
BIGNUM* encrypt(BIGNUM* msg, BIGNUM* ePublic, BIGNUM* nPbulic);

/* Uses RSA algorithm to decrypt the message passed. */
BIGNUM* decrypt(BIGNUM* encryptedMsg, BIGNUM* privateKey, BIGNUM* publicKey);

/* Prints out the big number. */
void printBN(char* msg, BIGNUM* a);

/* Prints out a hex number.  */
void  printHexString(const char* hexString);

/* Gets the length of the string passed. */
int getLength(char* theString);

/* Checks the character passed to determine if it is in the range of 33-126. */
char isValidAscii(char toCheck);

/* Converts a string of hexadecimal numbers to ASCII. */
void hexToAscii(char* toConvert);

/* Converts a string of hexadecimal digits into its integer equivalent. */
int hexToInt(char hexString[]);
