package com.lemoulinstudio.forest.platform.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

public class CryptoUtil {
  
  public static KeyPair importKeyPair(InputStream inputStream, char[] passPhrase, boolean armor)
          throws IOException, NoSuchProviderException, PGPException {
    if (armor) {
      inputStream = new ArmoredInputStream(inputStream);
    }
    
    PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(inputStream);
    
    PGPSecretKey secretKey = secretKeyRing.getSecretKey();
    PGPPublicKey publicKey = secretKey.getPublicKey();
    PGPPrivateKey privateKey = secretKey.extractPrivateKey(passPhrase, "BC");
    
    return new KeyPair(publicKey.getKey("BC"), privateKey.getKey());
  }
  
  public static PublicKey importPublicKey(InputStream inputStream, boolean armor)
          throws IOException, NoSuchProviderException, PGPException {
    
    if (armor) {
      inputStream = new ArmoredInputStream(inputStream);
    }
    
    PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(inputStream);
    
    return publicKeyRing.getPublicKey().getKey("BC");
  }

  public static void exportKeyPair(
          KeyPair keyPair,
          char[] passPhrase,
          String identity,
          OutputStream secretOut,
          OutputStream publicOut,
          boolean armor)
          throws NoSuchProviderException, InvalidKeyException, SignatureException, PGPException, IOException {
    if (armor) {
      secretOut = new ArmoredOutputStream(secretOut);
      publicOut = new ArmoredOutputStream(publicOut);
    }

    PGPSecretKey secretKey = new PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION,
            PGPPublicKey.RSA_GENERAL,
            keyPair.getPublic(),
            keyPair.getPrivate(),
            new Date(),
            identity,
            PGPEncryptedData.AES_256,
            passPhrase,
            null,
            null,
            new SecureRandom(),
            "BC");
    PGPPublicKey publicKey = secretKey.getPublicKey();

    secretKey.encode(secretOut);
    publicKey.encode(publicOut);

    if (armor) {
      secretOut.close();
      publicOut.close();
    }
  }
  
  public static void exportPublicKey(
          PublicKey publicKey,
          OutputStream outputStream,
          boolean armor)
          throws NoSuchProviderException, PGPException, IOException {
    PGPPublicKey pgpPublicKey = new PGPPublicKey(
            PGPPublicKey.RSA_GENERAL,
            publicKey,
            new Date(0),
            "BC");
    
    if (armor) {
      outputStream = new ArmoredOutputStream(outputStream);
    }
    
    pgpPublicKey.encode(outputStream);
    
    if (armor) {
      // Note: the underlying stream is not closed.
      outputStream.close();
    }
  }
  
}
