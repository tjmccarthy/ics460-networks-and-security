#include "rsa_functions.c"

int main(){
    printf("\nTask 1: Deriving the Private Key.\n");
    printf("___________________________________________________________________________\n");

    /* Initialize p and assign its large prime value from a hex number string. */
    BIGNUM* p = BN_new();
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");

    /* Initialize q and assign its large prime value from a hex number string. */
    BIGNUM* q = BN_new();
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");

    /* Initialize e and assign the prime value communicated in 3.1 Task 1. */
    BIGNUM* e = BN_new();
    BN_hex2bn(&e, "0D88C3");

    /* Output details involving the equation used to create a private key. */
    printf("Key generation using the RSA algorithm requires the approach detailed below.\n");
    printf("Let p and q represent any large random prime numbers and n = p * q. Using the totient\n");
    printf("function phi(n) = (p-1)*(q-1), we select a value for e that is relatively prime");
    printf(" to phi(n).\nThe private key can then be derived with the equation e*d = phi(n) where"); 
    printf(" d = the private key.\n\nWe are provided the following values of p, q, and e:\n");
    printBN("p = ", p);
    printBN("q = ", q);
    printBN("e = ", e);
    printf("\nThese values should yield a hexadecimal string that looks like\n");
    printf("3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB\nGenerating key...\n");

    // Derive and print the Private Key.
    BIGNUM* privateKey = generatePrivateKey(p, q, e);
    printBN("The private key, d = ", privateKey);
    return 0;
}
