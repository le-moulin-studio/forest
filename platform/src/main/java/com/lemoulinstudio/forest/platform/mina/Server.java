package com.lemoulinstudio.forest.platform.mina;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;

public class Server {
  
  private NioSocketAcceptor acceptor;
  
  public void start(KeyPair ownKeyPair,
          Set<PublicKey> contactsPublicKey,
          int port,
          IoHandler ioHandler) throws IOException {
    acceptor = new NioSocketAcceptor();
    acceptor.getFilterChain().addLast("handshake", new ServerHandshakeFilter(ownKeyPair, contactsPublicKey));
    acceptor.setHandler(ioHandler);
    acceptor.bind(new InetSocketAddress(port));
  }
  
  public void close() {
    acceptor.unbind();
  }
  
}
