package com.lemoulinstudio.forest.platform;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

public class KeyImporter {

  public static PublicKey importPublicKey(InputStream publicIn, boolean armor)
          throws IOException, NoSuchProviderException, PGPException {
    
    if (armor) {
      publicIn = new ArmoredInputStream(publicIn);
    }
    
    PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicIn);
    
    return publicKeyRing.getPublicKey().getKey("BC");
  }
  
}
