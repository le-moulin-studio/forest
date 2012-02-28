package com.lemoulinstudio.forest.platform.crypto;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureOutputStream extends OutputStream {
  
  private final Signature signature;

  public SignatureOutputStream(Signature signature) {
    this.signature = signature;
  }

  @Override
  public void write(int b) throws IOException {
    try {
      signature.update((byte) b);
    } catch (SignatureException e) {
      throw new IOException(e);
    }
  }

  @Override
  public void write(byte[] byteArray, int offset, int length) throws IOException {
    try {
      signature.update(byteArray, offset, length);
    } catch (SignatureException e) {
      throw new IOException(e);
    }
  }

}
