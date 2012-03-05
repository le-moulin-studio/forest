package com.lemoulinstudio.forest.platform.mina;

import javax.crypto.Cipher;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilter.NextFilter;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequest;
import org.apache.mina.filter.util.WriteRequestFilter;

public class CipherFilter extends WriteRequestFilter {
  
  public static final AttributeKey ENCRYPTION_CIPHER =
          new AttributeKey(CipherFilter.class, "encryptionCipher");
  
  public static final AttributeKey DECRYPTION_CIPHER =
          new AttributeKey(CipherFilter.class, "decryptionCipher");

  @Override
  public void messageReceived(NextFilter nextFilter, IoSession session, Object message) throws Exception {
    IoBuffer cipherTextBuffer = (IoBuffer) message;
    
    Cipher decryptionCipher = (Cipher) session.getAttribute(DECRYPTION_CIPHER);
    byte[] plainText = decryptionCipher.doFinal(cipherTextBuffer.array(), 0, cipherTextBuffer.limit());
    
    nextFilter.messageReceived(session, plainText);
  }

  @Override
  protected Object doFilterWrite(NextFilter nextFilter, IoSession session, WriteRequest writeRequest) throws Exception {
    byte[] plainText = (byte[]) writeRequest.getMessage();
    
    Cipher encryptionCipher = (Cipher) session.getAttribute(ENCRYPTION_CIPHER);
    IoBuffer cipherTextBuffer = IoBuffer.wrap(encryptionCipher.doFinal(plainText));
    
    return cipherTextBuffer;
  }

}
