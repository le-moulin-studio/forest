package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.handshake.ClientSecureConnectionHandler;
import java.security.KeyPair;
import java.security.PublicKey;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;

public class ClientHandshakeFilter extends IoFilterAdapter {
  
  private final AttributeKey HANDSHAKE_HANDLER = new AttributeKey(ClientHandshakeFilter.class, "handshakeHandler");

  private KeyPair ownKeyPair;
  private PublicKey contactPublicKey;

  public ClientHandshakeFilter(KeyPair ownKeyPair, PublicKey contactPublicKey) {
    this.ownKeyPair = ownKeyPair;
    this.contactPublicKey = contactPublicKey;
  }

  @Override
  public void sessionCreated(NextFilter nextFilter, IoSession session) throws Exception {
    // Don't forward the event to the next filter.
  }

  @Override
  public void sessionOpened(NextFilter nextFilter, IoSession session) throws Exception {
    // Creates an handshake handler and attach it to the session.
    ClientSecureConnectionHandler handshakeHandler = new ClientSecureConnectionHandler(ownKeyPair, contactPublicKey);
    session.setAttribute(HANDSHAKE_HANDLER, handshakeHandler);
    
    // Create and send the connection request.
    byte[] connectionRequest = handshakeHandler.createConnectionRequest();
    session.write(IoBuffer.wrap(connectionRequest));
    
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

  @Override
  public void messageReceived(NextFilter nextFilter, IoSession session, Object message) throws Exception {
    ClientSecureConnectionHandler handshakeHandler = (ClientSecureConnectionHandler) session.getAttribute(HANDSHAKE_HANDLER);
    
    IoBuffer connectionResponse = (IoBuffer) message;
    byte[] responseData = new byte[connectionResponse.limit()];
    connectionResponse.get(responseData);
    handshakeHandler.handleConnectionResponse(responseData);
    
    // We detach the handshake handler from the session.
    session.removeAttribute(HANDSHAKE_HANDLER);
    
    // We attach the encryption and decryption ciphers to the session.
    session.setAttribute(CipherFilter.ENCRYPTION_CIPHER, handshakeHandler.getEncryptionCipher());
    session.setAttribute(CipherFilter.DECRYPTION_CIPHER, handshakeHandler.getDecryptionCipher());
    
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
