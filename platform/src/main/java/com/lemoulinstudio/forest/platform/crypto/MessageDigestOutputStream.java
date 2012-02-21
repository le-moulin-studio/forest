package com.lemoulinstudio.forest.platform.crypto;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

public class MessageDigestOutputStream extends OutputStream {
  
  private final MessageDigest messageDigest;

  public MessageDigestOutputStream(MessageDigest messageDigest) {
    this.messageDigest = messageDigest;
  }

  @Override
  public void write(int b) throws IOException {
    messageDigest.update((byte) b);
  }

  @Override
  public void write(byte[] byteArray, int offset, int length) throws IOException {
    messageDigest.update(byteArray, offset, length);
  }

  public byte[] digest() {
    return messageDigest.digest();
  }
  
}
