#include "rsa_functions.c"

/* The task4.c program generates a signature for a message provided. After making a small
   adjustment to the message, a second signature is generated for comparison.          */
int main(){
    printf("Task 4: Signing a message.\n");
    printf("____________________________________________________________________\n");

    /* Create struct to hold BIGNUM temp variables. */
    BN_CTX* ctx = BN_CTX_new();

    /* Big number variable declaration for private key (d), and the public key (n). */
    BIGNUM* privateKey = BN_new();
    BIGNUM* nPublicKey = BN_new();

    /* Big number variable declaration for the two messages, and their signed forms. */
    BIGNUM* msg = BN_new();
    BIGNUM* msg2 = BN_new();
    BIGNUM* msgSigned = BN_new();
    BIGNUM* msg2Signed = BN_new();

    /* Initialize string values provided to validate code correctness. */
    char n[65] = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    char M[17] = "I owe you $2000.";
    char modifiedM[18] = "I owe you $2,000.";
    char hexOfM[33] = "49206F776520796F752024323030302E";
    char hexOfModifiedM[35] = "49206F776520796F752024322C3030302E";
    char d[65] = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";

    /* Initialize big number variables.  */
    BN_hex2bn(&privateKey, d);
    BN_hex2bn(&nPublicKey, n);
    BN_hex2bn(&msg, hexOfM);
    BN_hex2bn(&msg2, hexOfModifiedM);

    printf("For this task we sign the messages using M^private key mod public key equation.\n");

    /* Sign each of the messages. */
    BN_mod_exp(msgSigned, msg, privateKey, nPublicKey, ctx);
    BN_mod_exp(msg2Signed, msg2, privateKey, nPublicKey, ctx);

    /* Output values needed to verify code correctness. */
    printf("\nValues provided in order to validate program functionality:\n");
    printf("M = %s\n", M);
    printf("Hex equivalent of M = %s\n", hexOfM);
    printBN("First signed message:", msgSigned);
    printf("\nmodifiedM = %s\n", modifiedM);
    printf("Hex equivalent of modifiedM = %s\n", hexOfModifiedM);
    printBN("Second signed message:", msg2Signed);
    printf("____________________________________________________________");
    printf("___________________________\n\n");
}

