/* Implementation of the functions used in the RSA Lab. The logic used in the following
   functions are loosely based on examples provided in the slides that were included in the
   Lab resources provided on page 1 of Crypto_RSA.pdf.(handsonsecurity.net/resources.html) */
#include "rsa_functions.h"

/* Derive the private key from (e,n). Source - Slide 17/56 of Public_Key_Encryption.pptx. */
BIGNUM* generatePrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e){
    // Create the structure that holds the BIGNUM variable.
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* theKey = BN_new();
    // Create big number variables for finding e, 1 < e < Euler's totient function y(n).
    BIGNUM* pMinusOne = BN_new();
    BIGNUM* qMinusOne = BN_new();
    // Big number variables for extended Euclidean algorithm's equation e*d mod totFunc(n) = 1.
    BIGNUM* totFunc = BN_new();
    BIGNUM* one = BN_new();

    BN_dec2bn(&one, "1");   // Assign the value of the decimal number string to the variable.

    // Compute the values of p-1 and q-1 and assign results to their big number variables.
    BN_sub(pMinusOne, p, one);
    BN_sub(qMinusOne, q, one);

    // Assign value to Euler's totient function based off the product of (p-1)*(q-1).
    BN_mul(totFunc, pMinusOne, qMinusOne, ctx);

    // Compute the modular inverse and get the private key's value stored to return variable.
    BN_mod_inverse(theKey, e, totFunc, ctx);

    // Free the dynamic memory allocated to store big number in the ctx variable.
    BN_CTX_free(ctx);
    return theKey;
}

/* Uses RSA algorithm to encrypt a message using the public key provided. */
BIGNUM* encrypt(BIGNUM* msg, BIGNUM* ePublic, BIGNUM* nPublic){
    // Create the structure that holds the BIGNUM variable.
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* encryptedMsg = BN_new();

    // encryptedMsg = msg^mod pubKey: (a^c mod n:)
    BN_mod_exp(encryptedMsg, msg, ePublic, nPublic, ctx);
    // Free dynamic memory allocated to store BIGNUM variable contents.
    BN_CTX_free(ctx);
    return encryptedMsg;
}

/* Uses RSA algorithm to decrypt the message passed. */
BIGNUM* decrypt(BIGNUM* encryptedMsg, BIGNUM* privateKey, BIGNUM* publicKey){
    // Create the structure that holds the BIGNUM variable.
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* decryptedMsg = BN_new();

    // decryptedMsg = encryptedMsg^privKey pubKey: (a^c mod n:)
    BN_mod_exp(decryptedMsg, encryptedMsg, privateKey, publicKey, ctx);
    // Free dynamic memory allocated to store BIGNUM variable contents.
    BN_CTX_free(ctx);
    return decryptedMsg;
}

/* Print out a big number.  */
void printBN(char* msg, BIGNUM* a){
    char* number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

/* The decode function takes the string representation of the hex values and
   converts each grouping of 2 hex digits into their decimal value. This value
   is then used to determine the ASCII equivalent to decode the message.    */
void decode(char* hexString){
    int i = 0;
    char hexDigit;
}

/* Get the total number of characters in a string. */
int getLength(char* theString){
    char* string = theString;
    for (; *theString; theString++)
    return (theString - string);
}

/* Checks the value  passed to confirm it is in the apropriate ASCII range.
   Returns true (1) if character's value is in the range of 33 through 126
   otherwise returns false (0).                                          */
char isValidAscii(char toCheck){
    if (toCheck > 32 && toCheck < 127) return 1;
    return 0;
}

/* Converts a string of hexadecimal numbers to ASCII. Validates each character
   separated by an empty space.                                             */
void hexToAscii(char* toConvert){
    char hexString[(getLength(toConvert+1))];
    int i = 0;           // Variable for indexing within the while loop below.

    while (hexString[i] != '0'){
        printf("%2x", hexString[i]);
        i++;
        }
    putchar(hexString[i]);
}

/* Convert a hexadecimal string into its integer equivalent. Source of logic
   involved @github.com/uthcode/learntosolveit/source/cprogramming        */
int hexToInt(char hexString[]){
    int n = 0;               // Store the converted hexadecimal number.
    int hexdigit;            // Store each digit in hexadecimal.
    int inhex;               // Flag to verify it is a hex number.
    int i = 0;               // Counter variable.
    if (hexString[i] == '0'){
        ++i;
        if (hexString[i] == 'x' || hexString[i] == 'X') {++i;}
        }

    inhex = 1;

    for (;inhex == 1; ++i) {
        if (hexString[i] >= '0' && hexString[i] <= '9') hexdigit = hexString[i] - '0';
        else if (hexString[i] >= 'a' && hexString[i] <= 'f') hexdigit = hexString[i] -'a' + 10;
        else if (hexString[i] >= 'A' && hexString[i] <= 'F') hexdigit = hexString[i] -'A' + 10;
        else
            inhex = 0;
        if (inhex == 1) n= 16 * n + hexdigit;
        }
    return n;
}
