package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.handshake.ServerSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.User;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequest;

public class ServerHandshakeFilter extends IoFilterAdapter {
  
  private final User user;

  public ServerHandshakeFilter(User user) {
    this.user = user;
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
    ServerSecureConnectionHandler handshakeHandler = new ServerSecureConnectionHandler(user);
    
    // Redirects the message to the handshake handler.
    IoBuffer connectionRequest = (IoBuffer) message;
    byte[] requestData = new byte[connectionRequest.limit()];
    connectionRequest.get(requestData);
    byte[] responseData = handshakeHandler.handleConnectionRequest(requestData);
    
    // We attach the encryption and decryption ciphers to the session.
    session.setAttribute(CipherFilter.ENCRYPTION_CIPHER, handshakeHandler.getEncryptionCipher());
    session.setAttribute(CipherFilter.DECRYPTION_CIPHER, handshakeHandler.getDecryptionCipher());
    
    // We attach some information about the connection.
    session.setAttribute(ForestIoHandler.INITIATED_BY_ME, Boolean.FALSE);
    session.setAttribute(ForestIoHandler.USER, user);
    session.setAttribute(ForestIoHandler.CONTACT, handshakeHandler.getContact());
    
    // Sends the response.
    session.write(IoBuffer.wrap(responseData));
    
    // Don't forward the event to the next filter.
  }

  @Override
  public void messageSent(NextFilter nextFilter, IoSession session, WriteRequest writeRequest) throws Exception {
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
