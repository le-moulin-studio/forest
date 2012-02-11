package com.lemoulinstudio.forest.platform;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;

public class KeyExporter {

  public static void exportKeyPair(
          User user,
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
            user.getPublicKey(),
            user.getPrivateKey(),
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
          OutputStream publicOut,
          boolean armor)
          throws NoSuchProviderException, PGPException, IOException {
    PGPPublicKey pgpPublicKey = new PGPPublicKey(
            PGPPublicKey.RSA_GENERAL,
            publicKey,
            new Date(),
            "BC");
    
    if (armor) {
      publicOut = new ArmoredOutputStream(publicOut);
    }
    
    pgpPublicKey.encode(publicOut);
    
    if (armor) {
      publicOut.close();
    }
  }
}
