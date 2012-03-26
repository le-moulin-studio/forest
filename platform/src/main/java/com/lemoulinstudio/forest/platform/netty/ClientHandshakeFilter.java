package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.handshake.ClientSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder;
import org.jboss.netty.handler.codec.frame.LengthFieldPrepender;

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
    
    // Clears the pipeline.
    ChannelPipeline pipeline = ctx.getPipeline();
    for (ChannelHandler handler : pipeline.toMap().values())
      pipeline.remove(handler);
    
    // Rebuild the pipeline.
    pipeline.addLast("cipher", new CipherFilter(handshakeHandler.getEncryptionCipher(),
                                                 handshakeHandler.getDecryptionCipher()));
    pipeline.addLast("frameDecoder", new LengthFieldBasedFrameDecoder(100 * 1024, 0, 4, 0, 4));
    pipeline.addLast("frameEncoder", new LengthFieldPrepender(4));
    pipeline.addLast("small", new ForestChannelHandler(true, user, contact));
    
    // We notify the handlers in the new pipeline about the state of the channel.
    Channels.fireChannelOpen(ctx.getChannel());
    Channels.fireChannelConnected(ctx.getChannel(), e.getRemoteAddress());
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
    e.getCause().printStackTrace();
    ctx.getChannel().close();
  }
  
}
