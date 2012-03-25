package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.handshake.ClientSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;

public class ClientHandshakeFilter extends SimpleChannelUpstreamHandler {
  
  private final User user;
  private final Contact contact;
  private final ClientSecureConnectionHandler handshakeHandler;

  public ClientHandshakeFilter(User user, Contact contact) {
    this.user = user;
    this.contact = contact;
    this.handshakeHandler = new ClientSecureConnectionHandler(user, contact);
  }

  @Override
  public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    // Create and send the connection request.
    byte[] connectionRequest = handshakeHandler.createConnectionRequest();
    ctx.getChannel().write(ChannelBuffers.wrappedBuffer(connectionRequest));
  }

  @Override
  public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
    ChannelBuffer connectionResponse = (ChannelBuffer) e.getMessage();
    byte[] responseData = new byte[connectionResponse.readableBytes()];
    connectionResponse.readBytes(responseData);
    handshakeHandler.handleConnectionResponse(responseData);
    
//    // We attach the encryption and decryption ciphers to the session.
//    session.setAttribute(CipherFilter.ENCRYPTION_CIPHER, handshakeHandler.getEncryptionCipher());
//    session.setAttribute(CipherFilter.DECRYPTION_CIPHER, handshakeHandler.getDecryptionCipher());
    
//    // We attach some information about the connection.
//    session.setAttribute(ForestIoHandler.INITIATED_BY_ME, Boolean.TRUE);
//    session.setAttribute(ForestIoHandler.USER, user);
//    session.setAttribute(ForestIoHandler.CONTACT, contact);
    
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
    
    ctx.getChannel().close();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
    e.getCause().printStackTrace();
    ctx.getChannel().close();
  }
  
}
