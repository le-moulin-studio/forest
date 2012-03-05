package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.handshake.ServerSecureConnectionHandler;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequest;

public class ServerHandshakeFilter extends IoFilterAdapter {
  
  public static final AttributeKey HIS_PUBLIC_KEY = new AttributeKey(ServerHandshakeFilter.class, "hisPublicKey");

  private KeyPair ownKeyPair;
  private Set<PublicKey> contactsPublicKey;
  
  public ServerHandshakeFilter(KeyPair ownKeyPair, Set<PublicKey> contactsPublicKey) {
    this.ownKeyPair = ownKeyPair;
    this.contactsPublicKey = contactsPublicKey;
  }

  @Override
  public void sessionCreated(NextFilter nextFilter, IoSession session) throws Exception {
    // Don't forward the event to the next filter.
  }

  @Override
  public void sessionOpened(NextFilter nextFilter, IoSession session) throws Exception {
    // Don't forward the event to the next filter.
  }

  @Override
  public void sessionIdle(NextFilter nextFilter, IoSession session, IdleStatus status) throws Exception {
    // Don't forward the event to the next filter.
  }

  @Override
  public void sessionClosed(NextFilter nextFilter, IoSession session) throws Exception {
    // Don't forward the event to the next filter.
  }

  /**
   * For the server, the validation of the session depends on the first message of the handshake.
   */
  @Override
  public void messageReceived(NextFilter nextFilter, IoSession session, Object message) throws Exception {
    // Creates an handshake handler and attach it to the session.
    ServerSecureConnectionHandler handshakeHandler = new ServerSecureConnectionHandler(ownKeyPair, contactsPublicKey);
    
    // Redirects the message to the handshake handler.
    IoBuffer connectionRequest = (IoBuffer) message;
    byte[] requestData = new byte[connectionRequest.limit()];
    connectionRequest.get(requestData);
    byte[] responseData = handshakeHandler.handleConnectionRequest(requestData);
    
    // We attach the public key of the remote user to the session.
    session.setAttribute(HIS_PUBLIC_KEY, handshakeHandler.getHisPublicKey());
    
    // We attach the encryption and decryption ciphers to the session.
    session.setAttribute(CipherFilter.ENCRYPTION_CIPHER, handshakeHandler.getEncryptionCipher());
    session.setAttribute(CipherFilter.DECRYPTION_CIPHER, handshakeHandler.getDecryptionCipher());
    
    // Sends the response.
    session.write(IoBuffer.wrap(responseData));
    
    // Don't forward the event to the next filter.
  }

  @Override
  public void messageSent(NextFilter nextFilter, IoSession session, WriteRequest writeRequest) throws Exception {
    // We create the next filter and add it to the filter chain.
    CipherFilter cipherFilter = new CipherFilter();
    session.getFilterChain().getEntry(this).addAfter("cipher", cipherFilter);
    
    // We notify the next filter about a created session.
    nextFilter.sessionCreated(session);
    nextFilter.sessionOpened(session);
    
    // We remove this filter from the filter chain.
    session.getFilterChain().remove(this);
    
    // Don't forward the event to the next filter.
  }

  @Override
  public void exceptionCaught(NextFilter nextFilter, IoSession session, Throwable cause) throws Exception {
    cause.printStackTrace();
    session.close(true);
    
    // Don't forward the event to the next filter.
  }
  
}
