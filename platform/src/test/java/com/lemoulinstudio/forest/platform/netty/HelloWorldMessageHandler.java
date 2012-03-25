package com.lemoulinstudio.forest.platform.netty;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;

public class HelloWorldMessageHandler extends SimpleChannelHandler {
  
  private final boolean isServerSide;

  public HelloWorldMessageHandler(boolean isServerSide) {
    this.isServerSide = isServerSide;
  }

  @Override
  public void channelBound(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    System.out.println(String.format("%s channel bound.", isServerSide ? "Server" : "Client"));
  }
  
  @Override
  public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    System.out.println(String.format("%s channel closed.", isServerSide ? "Server" : "Client"));
  }

  @Override
  public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    if (!isServerSide)
      ctx.getChannel().write(ChannelBuffers.wrappedBuffer("Hello Server!".getBytes()));
  }

  @Override
  public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
    ChannelBuffer buffer = (ChannelBuffer) e.getMessage();
    byte[] b = new byte[buffer.readableBytes()];
    buffer.readBytes(b);
    
    System.out.println(String.format("%s received: \"%s\"",
            isServerSide ? "Server" : "Client", new String(b)));
    
    if (isServerSide) {
      ChannelFuture channelFuture = ctx.getChannel().write(
              ChannelBuffers.wrappedBuffer("Hello Client!".getBytes()));
      channelFuture.addListener(ChannelFutureListener.CLOSE);
    }
    else {
      ctx.getChannel().close();
    }
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
    e.getCause().printStackTrace();
    
    ctx.getChannel().close();
  }
  
}
