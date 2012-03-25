package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.handshake.ServerSecureConnectionHandler;
import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.jboss.netty.handler.codec.frame.FixedLengthFrameDecoder;

public class Client {
  
  private ChannelFactory channelFactory;
  private Channel channel;
  
  public void connect(final User user, final Contact contact) throws Exception {
    connect(user, contact, new ChannelPipelineFactory() {
      @Override
      public ChannelPipeline getPipeline() {
        return Channels.pipeline(
                new FixedLengthFrameDecoder(ServerSecureConnectionHandler.connectionResponseSizeInBytes),
                new ClientHandshakeFilter(user, contact));
      }
    });
  }
  
  public void connect(User user, Contact contact, ChannelPipelineFactory channelPipelineFactory) throws Exception {
    channelFactory = new NioClientSocketChannelFactory(
            Executors.newCachedThreadPool(),
            Executors.newCachedThreadPool());
    
    ClientBootstrap bootstrap = new ClientBootstrap(channelFactory);
    bootstrap.setPipelineFactory(channelPipelineFactory);
    bootstrap.setOption("tcpNoDelay", true);
    bootstrap.setOption("keepAlive", true);
    
    ChannelFuture future = bootstrap.connect(new InetSocketAddress(contact.getInternetAddress(), contact.getPort()));    
    future.awaitUninterruptibly();
    
    if (future.isSuccess()) {
      channel = future.getChannel();
    }
    else {
      future.getCause().printStackTrace();
      throw new Exception(future.getCause());
    }
  }
  
  public void close() {
    channel.getCloseFuture().awaitUninterruptibly();
    channelFactory.releaseExternalResources();
  }

}
