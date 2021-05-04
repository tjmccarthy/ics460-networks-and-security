#include "rsa_functions.c"

/* The task3.c program performs decryption on the hexadecimal string provided. */
int main(){
    printf("Task 3: Decrypting a message.\n");
    printf("____________________________________________________________________\n");

    /* Big number variable declaration for private key (d), and the public key (n). */
    BIGNUM* privateKey = BN_new();
    BIGNUM* nPublicKey = BN_new();

    /* Big number variable declaration for the encrypted and decrypted forms. */
    BIGNUM* encryptedM = BN_new();
    BIGNUM* decryptedM = BN_new();

    /* Initialize string values provided to validate code correctness. */
    char n[65] = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    char hexOfM[27] = "4120746F702073656372657421";
    char d[65] = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
    char C[65] = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";

    /* Initialize big number variables.  */
    BN_hex2bn(&privateKey, d);
    BN_hex2bn(&nPublicKey, n);
    BN_hex2bn(&encryptedM, C);

    printf("For this task we decrypt the provided cyphertext C which yields the hexadecimal ");
    printf("string:\n50617373776F72642069732064656573.\n");

    /* Perform the decryption on the message. */
    decryptedM = decrypt(encryptedM, privateKey, nPublicKey);

    /* Output values needed to verify code correctness. */
    printf("\nThe cyphertext C = %s\n", C);
    printBN("C after decryption =", decryptedM);
    printf("\n____________________________________________________________________\n");
}
