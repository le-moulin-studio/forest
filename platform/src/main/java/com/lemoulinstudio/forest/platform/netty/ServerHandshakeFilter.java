package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.handshake.ServerSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.User;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.WriteCompletionEvent;

public class ServerHandshakeFilter extends SimpleChannelUpstreamHandler {
  
  private final User user;

  public ServerHandshakeFilter(User user) {
    this.user = user;
  }

  /**
   * For the server, the validation of the session depends on the first message of the handshake.
   */
  @Override
  public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
    // Creates an handshake handler and attach it to the session.
    ServerSecureConnectionHandler handshakeHandler = new ServerSecureConnectionHandler(user);
    
    // Redirects the message to the handshake handler.
    ChannelBuffer connectionRequest = (ChannelBuffer) e.getMessage();
    byte[] requestData = new byte[connectionRequest.readableBytes()];
    connectionRequest.readBytes(requestData);
    byte[] responseData = handshakeHandler.handleConnectionRequest(requestData);
    
//    // We attach the encryption and decryption ciphers to the session.
//    session.setAttribute(CipherFilter.ENCRYPTION_CIPHER, handshakeHandler.getEncryptionCipher());
//    session.setAttribute(CipherFilter.DECRYPTION_CIPHER, handshakeHandler.getDecryptionCipher());
//    
//    // We attach some information about the connection.
//    session.setAttribute(ForestIoHandler.INITIATED_BY_ME, Boolean.FALSE);
//    session.setAttribute(ForestIoHandler.USER, user);
//    session.setAttribute(ForestIoHandler.CONTACT, handshakeHandler.getContact());
    
    // Sends the response.
    ctx.getChannel().write(ChannelBuffers.wrappedBuffer(responseData));
  }

  @Override
  public void writeComplete(ChannelHandlerContext ctx, WriteCompletionEvent e) throws Exception {
//    // We create the cipher filter and add it to the filter chain.
//    session.getFilterChain().getEntry(this).addAfter("cipher", CipherFilter.getInstance());
//    
//    // We create the codec filter and add it to the filter chain.
//    session.getFilterChain().getEntry("cipher").addAfter("codec", PacketFilter.getInstance());
//        
//    // We remove this filter from the filter chain.
//    session.getFilterChain().remove(this);
//    
//    // We notify the next filter about a created session.
//    nextFilter.sessionCreated(session);
//    nextFilter.sessionOpened(session);
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
    e.getCause().printStackTrace();
    ctx.getChannel().close();
  }
  
}
