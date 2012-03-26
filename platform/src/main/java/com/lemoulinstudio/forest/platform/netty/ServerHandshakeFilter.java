package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.handshake.ServerSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.User;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DownstreamMessageEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder;
import org.jboss.netty.handler.codec.frame.LengthFieldPrepender;

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
    
    // Sends the response.
    ctx.sendDownstream(new DownstreamMessageEvent(
            ctx.getChannel(),
            e.getFuture(),
            ChannelBuffers.wrappedBuffer(responseData),
            null));
    
    // Clears the pipeline.
    ChannelPipeline pipeline = ctx.getPipeline();
    for (ChannelHandler handler : pipeline.toMap().values())
      pipeline.remove(handler);
    
    // Rebuild the pipeline.
    pipeline.addLast("cipher", new CipherFilter(handshakeHandler.getEncryptionCipher(),
                                                 handshakeHandler.getDecryptionCipher()));
    pipeline.addLast("frameDecoder", new LengthFieldBasedFrameDecoder(100 * 1024, 0, 4, 0, 4));
    pipeline.addLast("frameEncoder", new LengthFieldPrepender(4));
    pipeline.addLast("small", new ForestChannelHandler(false, user, handshakeHandler.getContact()));
    
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
