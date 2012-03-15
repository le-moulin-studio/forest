package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.handshake.ClientSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;

public class ClientHandshakeFilter extends IoFilterAdapter {
  
  private final AttributeKey HANDSHAKE_HANDLER = new AttributeKey(ClientHandshakeFilter.class, "handshakeHandler");

  private final User user;
  private final Contact contact;

  public ClientHandshakeFilter(User user, Contact contact) {
    this.user = user;
    this.contact = contact;
  }

  @Override
  public void sessionCreated(NextFilter nextFilter, IoSession session) throws Exception {
    // Don't forward the event to the next filter.
  }

  @Override
  public void sessionOpened(NextFilter nextFilter, IoSession session) throws Exception {
    // Creates an handshake handler and attach it to the session.
    ClientSecureConnectionHandler handshakeHandler = new ClientSecureConnectionHandler(user, contact);
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
    
    // We attach some information about the connection.
    session.setAttribute(ForestIoHandler.INITIATED_BY_ME, Boolean.TRUE);
    session.setAttribute(ForestIoHandler.USER, user);
    session.setAttribute(ForestIoHandler.CONTACT, contact);
    
    // We create the cipher filter and add it to the filter chain.
    session.getFilterChain().getEntry(this).addAfter("cipher", CipherFilter.getInstance());
    
    // We create the codec filter and add it to the filter chain.
    session.getFilterChain().getEntry("cipher").addAfter("codec", PacketFilter.getInstance());
    
    // We remove this filter from the filter chain.
    session.getFilterChain().remove(this);
    
    // We notify the next filter about a created session.
    nextFilter.sessionCreated(session);
    nextFilter.sessionOpened(session);
    
    // Don't forward the event to the next filter.
  }

  @Override
  public void exceptionCaught(NextFilter nextFilter, IoSession session, Throwable cause) throws Exception {
    cause.printStackTrace();
    session.close(true);
    
    // Don't forward the event to the next filter.
  }
  
}
