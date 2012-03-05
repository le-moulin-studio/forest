package com.lemoulinstudio.forest.platform.mina;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;

public class Client {
  
  public IoSession connect(KeyPair ownKeyPair,
          PublicKey contactPublicKey,
          String hostname,
          int port,
          IoHandler ioHandler) {
    NioSocketConnector connector = new NioSocketConnector();
    connector.getFilterChain().addLast("handshake", new ClientHandshakeFilter(ownKeyPair, contactPublicKey));
    connector.setHandler(ioHandler);
    
    ConnectFuture connectFuture = connector.connect(new InetSocketAddress(hostname, port));
    connectFuture.awaitUninterruptibly();
    return connectFuture.getSession();
  }

}
