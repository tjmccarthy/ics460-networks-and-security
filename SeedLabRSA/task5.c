#include "rsa_functions.c"

/* The task5.c program performs decryption on a signature using public key (e,n)
   to verify the signature.                                                   */
int main(){
    printf("Task 5: Verifying a signature.\n");
    printf("____________________________________________________________________________\n");

    /* Big number variable declarations. */
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* signature = BN_new();
    BIGNUM* corruptedSignature = BN_new();
    BIGNUM* nPublicKey = BN_new();
    BIGNUM* ePublicKey = BN_new();
    BIGNUM* message = BN_new();

    char* e = "010001";
    char* n = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";
    char* s = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
    char* corruptS = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F";
    char* m = "4C61756E63682061206D697373696C652E";

    printf("Bob receives the message %s or \"Launch a missile.\"\n", m);
    printf("The sender Alice, has a public key with values e = %s, and\nn = %s\n", e, n);
    printf("We verify her signature %s by\ncalculating s^e mod n which should produce the message Bob received.\n", s);
    printf("________________________________________________________________________\n");

    /* Initialize Bignumber variables. */
    BN_hex2bn(&ePublicKey, e);
    BN_hex2bn(&nPublicKey, n);
    BN_hex2bn(&signature, s);
    BN_hex2bn(&corruptedSignature, corruptS);

    /* Verify signature by calculating s^e mod n which will give us the message. */
    BN_mod_exp(message, signature, ePublicKey, nPublicKey, ctx);
    printBN("\nVerifying message with Alice's signature:", message);

    printf("Verified so....BOOM, but lets try to verify with a signature with one different character, say\n%s\n", corruptS);

    /* Attempting to verify a corrupt signature with last 2 hex digits 3F instead of 2F. */
    BN_mod_exp(message, corruptedSignature, ePublicKey, nPublicKey, ctx);
    printBN("\nVerifying message with the corrupted signature:", message);
    printf("\nA completely different and invalid message is produced.\n");
    printf("_______________________________________________________________________________\n");
}
