#include "rsa_functions.c"

/* The task2.c program encrypts a hexadecimal string representing ascii characters of the message. */
int main(){
    printf("Task 2: Encrypting a message.\n");
    printf("____________________________________________________________________\n");

    /* Big number variable declaration for private key (d), and the public key (e,n) respectively. */
    BIGNUM* privateKey = BN_new();
    BIGNUM* ePublicKey = BN_new();
    BIGNUM* nPublicKey = BN_new();

    /* Big number variable declaration for the message, and its encrypted/decrypted forms. */
    BIGNUM* msg = BN_new();
    BIGNUM* encryptedM = BN_new();

    /* Initialize string values provided to validate code correctness. */
    char e[6] = "65537";
    char n[65] = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    char M[14] = "A top secret!";
    char hexOfM[27] = "4120746F702073656372657421";
    char d[65] = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";

    /* Initialize big number variables.  */
    BN_hex2bn(&privateKey, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_dec2bn(&ePublicKey, "010001");
    BN_hex2bn(&nPublicKey, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&msg, hexOfM);

    printf("For this task we encrypt the message M, which in ascii is \"A top secret!\"\n");

    /* Perform the encryption on the message. */
    encryptedM = encrypt(msg, ePublicKey, nPublicKey);

    /* Output values needed to verify code correctness. */
    printf("\nValues provided in order to validate program functionality:\n");
    printf("M = %s\n", M);
    printf("Hex equivalent of M = %s\n", hexOfM);
    printBN("\nThe encrypted message is", encryptedM);
    printf("____________________________________________________________________\n\n");
}
