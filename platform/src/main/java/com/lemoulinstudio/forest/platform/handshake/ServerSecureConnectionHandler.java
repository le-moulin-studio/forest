package com.lemoulinstudio.forest.platform.handshake;

import java.security.KeyPair;
import java.security.PublicKey;

public class ServerSecureConnectionHandler extends SecureConnectionHandler {

  public ServerSecureConnectionHandler(KeyPair ownKeyPair, PublicKey hisPublicKey) {
    super(ownKeyPair, hisPublicKey);
  }

  public byte[] handleConnectionRequest(byte[] requestData)
          throws InvalidMessage {
    return null;
  }
  
}
