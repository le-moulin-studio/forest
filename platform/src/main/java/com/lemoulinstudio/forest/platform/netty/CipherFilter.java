package com.lemoulinstudio.forest.platform.netty;

import javax.crypto.Cipher;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.DownstreamMessageEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.channel.UpstreamMessageEvent;

public class CipherFilter extends SimpleChannelHandler {
  
  private final Cipher encryptionCipher;
  private final Cipher decryptionCipher;

  public CipherFilter(Cipher encryptionCipher, Cipher decryptionCipher) {
    this.encryptionCipher = encryptionCipher;
    this.decryptionCipher = decryptionCipher;
  }

  @Override
  public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
    ChannelBuffer cipherTextBuffer = (ChannelBuffer) e.getMessage();
    
    byte[] plainText = decryptionCipher.doFinal(
            cipherTextBuffer.array(),
            0,
            cipherTextBuffer.readableBytes());
    
    ctx.sendUpstream(new UpstreamMessageEvent(
            ctx.getChannel(),
            ChannelBuffers.wrappedBuffer(plainText),
            e.getRemoteAddress()));
  }

  @Override
  public void writeRequested(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
    ChannelBuffer plainTextBuffer = (ChannelBuffer) e.getMessage();
    byte[] plainText = new byte[plainTextBuffer.readableBytes()];
    plainTextBuffer.readBytes(plainText);
    
    byte[] cipherText = encryptionCipher.doFinal(plainText);
    
    ctx.sendDownstream(new DownstreamMessageEvent(
            ctx.getChannel(),
            e.getFuture(),
            ChannelBuffers.wrappedBuffer(cipherText),
            e.getRemoteAddress()));
  }

}
