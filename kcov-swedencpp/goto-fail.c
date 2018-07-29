#include <stdint.h>
#include <stdio.h>

typedef int bool;
typedef int OSStatus;
typedef uint16_t UInt16;

typedef struct
{
  void *clientRandom;
  void *serverRandom;
  void *peerPubKey;
} SSLContext;
#define SSL_CLIENT_SRVR_RAND_SIZE 4
#define SSL_SHA1_DIGEST_LEN 5
#define SSL_MD5_DIGEST_LEN 10

typedef struct
{
  void *data;
  unsigned length;
} SSLBuffer;

int very_dummy_update(void *a, void *b)
{
  return 0;
}

struct _SSLHashMD5
{
  int (*update)(void *, void *);
  int (*final)(void *, void *);
};

struct _SSLHashMD5 SSLHashMD5;

struct _SSLHashSHA1
{
  int (*update)(void *, void *);
  int (*final)(void *, void *);
};

struct _SSLHashSHA1 SSLHashSHA1;


int ReadyHash(void *a, void *b)
{
  return 0;
}

int sslRawVerify(SSLContext *ctx,
         void *peerPubKey,
                 void *dataToSign,
                 unsigned dataToSignLen,
                 void *signature,
                 unsigned signatureLen)
{
  return 0;
}

int SSLFreeBuffer(void *p)
{
  return 0;
}

#define sslErrorLog printf



static OSStatus
SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa, SSLBuffer signedParams,
                                 uint8_t *signature, UInt16 signatureLen)
{
    OSStatus        err;
    SSLBuffer       hashOut, hashCtx, clientRandom, serverRandom;
    uint8_t         hashes[SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN];
    SSLBuffer       signedHashes;
    uint8_t            *dataToSign;
    size_t            dataToSignLen;

    signedHashes.data = 0;
    hashCtx.data = 0;

    clientRandom.data = ctx->clientRandom;
    clientRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;
    serverRandom.data = ctx->serverRandom;
    serverRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;


    if(isRsa) {
        /* skip this if signing with DSA */
        dataToSign = hashes;
        dataToSignLen = SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN;
        hashOut.data = hashes;
        hashOut.length = SSL_MD5_DIGEST_LEN;
        
        if ((err = ReadyHash(&SSLHashMD5, &hashCtx)) != 0)
            goto fail;
        if ((err = SSLHashMD5.update(&hashCtx, &clientRandom)) != 0)
            goto fail;
        if ((err = SSLHashMD5.update(&hashCtx, &serverRandom)) != 0)
            goto fail;
        if ((err = SSLHashMD5.update(&hashCtx, &signedParams)) != 0)
            goto fail;
        if ((err = SSLHashMD5.final(&hashCtx, &hashOut)) != 0)
            goto fail;
    }
    else {
        /* DSA, ECDSA - just use the SHA1 hash */
        dataToSign = &hashes[SSL_MD5_DIGEST_LEN];
        dataToSignLen = SSL_SHA1_DIGEST_LEN;
    }

    hashOut.data = hashes + SSL_MD5_DIGEST_LEN;
    hashOut.length = SSL_SHA1_DIGEST_LEN;
    if ((err = SSLFreeBuffer(&hashCtx)) != 0)
        goto fail;

    if ((err = ReadyHash(&SSLHashSHA1, &hashCtx)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
        goto fail;
        goto fail;
    if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0)
        goto fail;

    err = sslRawVerify(ctx,
                       ctx->peerPubKey,
                       dataToSign,                /* plaintext */
                       dataToSignLen,            /* plaintext length */
                       signature,
                       signatureLen);
    if(err) {
        sslErrorLog("SSLDecodeSignedServerKeyExchange: sslRawVerify "
                    "returned %d\n", (int)err);
        goto fail;
    }

fail:
    SSLFreeBuffer(&signedHashes);
    SSLFreeBuffer(&hashCtx);
    return err;

}









int main(int argc, const char *argv[])
{
  SSLHashSHA1.final = very_dummy_update;
  SSLHashSHA1.update = very_dummy_update;

  SSLHashMD5.final = very_dummy_update;
  SSLHashMD5.update = very_dummy_update;

  SSLContext ctx;
  SSLBuffer buf;

  SSLVerifySignedServerKeyExchange(&ctx, 0, buf, "Kalle anka", 5);
}
