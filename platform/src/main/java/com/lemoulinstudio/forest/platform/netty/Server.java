package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.user.User;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.group.ChannelGroupFuture;
import org.jboss.netty.channel.group.DefaultChannelGroup;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;

public class Server {
  
  private ChannelFactory channelFactory;
  
  private final ChannelGroup channelGroup = new DefaultChannelGroup("forest server");
  
  public void start(User user) throws IOException {
    start(user, new ChannelPipelineFactory() {
      @Override
      public ChannelPipeline getPipeline() {
        return Channels.pipeline(new ForestChannelHandler());
      }
    });
  }
  
  public void start(User user, ChannelPipelineFactory channelPipelineFactory) throws IOException {
    channelFactory = new NioServerSocketChannelFactory(
        Executors.newCachedThreadPool(),
        Executors.newCachedThreadPool());
    
    ServerBootstrap bootstrap = new ServerBootstrap(channelFactory);
    bootstrap.setPipelineFactory(channelPipelineFactory);
    bootstrap.setOption("child.tcpNoDelay", true);
    bootstrap.setOption("child.keepAlive", true);
    Channel channel = bootstrap.bind(new InetSocketAddress(user.getPort()));    
    
    channelGroup.add(channel);
  }
  
  public void close() {
    ChannelGroupFuture channelGroupFuture = channelGroup.close();
    channelGroupFuture.awaitUninterruptibly();
    channelFactory.releaseExternalResources();
  }
  
}
