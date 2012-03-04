package com.lemoulinstudio.forest.platform.handshake;

import com.lemoulinstudio.forest.platform.User;
import com.lemoulinstudio.forest.platform.UserFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

public class SecureConnectionHandlerTest {
  
  public static final int userKeysize = 4096;
  
  public static User alice;
  public static User bob;
  
  @BeforeClass
  public static void setupBouncyCastle() throws Exception {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
    
    UserFactory userFactory = new UserFactory(userKeysize);
    alice = userFactory.createUser("Alice");
    bob = userFactory.createUser("Bob");
  }
  
  @Test
  public void testConstantSizeOfRequestAndResponse() throws Exception {
    ClientSecureConnectionHandler clientHandler = new ClientSecureConnectionHandler(
            alice.getKeyPair(),
            bob.getKeyPair().getPublic());
    
    ServerSecureConnectionHandler serverHandler = new ServerSecureConnectionHandler(
            bob.getKeyPair(),
            Collections.singleton((RSAPublicKey) alice.getKeyPair().getPublic()));
    
    byte[] connectionRequest = clientHandler.createConnectionRequest();
    byte[] connectionResponse = serverHandler.handleConnectionRequest(connectionRequest);
    
    int expectedRequestSize = connectionRequest.length;
    int expectedResponseSize = connectionResponse.length;
    
    for (int i = 0; i < 16; i++) {
      connectionRequest = clientHandler.createConnectionRequest();
      connectionResponse = serverHandler.handleConnectionRequest(connectionRequest);
      assertEquals(connectionRequest.length, expectedRequestSize);
      assertEquals(connectionResponse.length, expectedResponseSize);
    }
    
    //System.out.println("Expected request size = " + expectedRequestSize);
    //System.out.println("Expected response size = " + expectedResponseSize);
  }
  
  private void testEncryptedCommunicationChannel(
          Cipher encryptionCipher,
          Cipher decryptionCipher,
          byte[] message) throws IOException {
      ByteArrayOutputStream encryptedArray = new ByteArrayOutputStream();
      CipherOutputStream encryptionOutputStream = new CipherOutputStream(encryptedArray, encryptionCipher);
      encryptionOutputStream.write(message);
      encryptionOutputStream.flush(); // Note: it doesn't totally flush for block ciphers.
      encryptionOutputStream.close(); // .. so we still need to close.
      byte[] encryptedMessage = encryptedArray.toByteArray();
      
      ByteArrayOutputStream decryptedArray = new ByteArrayOutputStream();
      CipherOutputStream decryptionOutputStream = new CipherOutputStream(decryptedArray, decryptionCipher);
      decryptionOutputStream.write(encryptedMessage);
      decryptionOutputStream.flush(); // Note: it doesn't totally flush for block ciphers.
      decryptionOutputStream.close(); // .. so we still need to close.
      byte[] decryptedMessage = decryptedArray.toByteArray();
      
      assertArrayEquals("The message should be the same before encryption and after decryption",
              message, decryptedMessage);
  }

  @Test
  public void testHandshake() throws Exception {
    ClientSecureConnectionHandler clientHandler = new ClientSecureConnectionHandler(
            alice.getKeyPair(),
            bob.getKeyPair().getPublic());
    
    ServerSecureConnectionHandler serverHandler = new ServerSecureConnectionHandler(
            bob.getKeyPair(),
            Collections.singleton((RSAPublicKey) alice.getKeyPair().getPublic()));
    
    // Establishes a connection.
    byte[] connectionRequest = clientHandler.createConnectionRequest();
    byte[] connectionResponse = serverHandler.handleConnectionRequest(connectionRequest);
    clientHandler.handleConnectionResponse(connectionResponse);
    
    // Random message to be exchanged between the client and the server.
    byte[] testMessage = new byte[1024];
    new SecureRandom().nextBytes(testMessage);
    
    // Tests the communication channel client->server.
    testEncryptedCommunicationChannel(
            clientHandler.getEncryptionCipher(),
            serverHandler.getDecryptionCipher(),
            testMessage);
    
    // Tests the communication channel server->client.
    testEncryptedCommunicationChannel(
            serverHandler.getEncryptionCipher(),
            clientHandler.getDecryptionCipher(),
            testMessage);
  }
  
}
