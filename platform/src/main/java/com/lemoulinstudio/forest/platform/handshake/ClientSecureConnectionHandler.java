package com.lemoulinstudio.forest.platform.handshake;

import com.lemoulinstudio.forest.platform.crypto.CryptoUtil;
import com.lemoulinstudio.forest.platform.crypto.SignatureOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.BigIntegers;

public class ClientSecureConnectionHandler extends SecureConnectionHandler {

  public ClientSecureConnectionHandler(KeyPair ownKeyPair, PublicKey hisPublicKey) {
    super(ownKeyPair, hisPublicKey);
  }

  // TODO: Understand why one should never use the same RSA key to sign and to encrypt,
  // and rectify Forest if needed.
  public byte[] createConnectionRequest() throws Exception {
    SecureRandom secureRandom = new SecureRandom();
    
    // This is the holder of the request.
    ByteArrayOutputStream requestOutputStream = new ByteArrayOutputStream(2048);
    
    // Generates my DH key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", jceProviderName);
    keyPairGenerator.initialize(dhParameterSpec, secureRandom);
    KeyPair dhKeyPair = keyPairGenerator.generateKeyPair();
    myDhPublicKey = (DHPublicKey) dhKeyPair.getPublic();
    myDhPrivateKey = (DHPrivateKey) dhKeyPair.getPrivate();
    
    // Encrypts the DH public key with the hisPublicKey.
    Cipher rsaCipher = Cipher.getInstance(asymmetricCipherDesc, jceProviderName);
    rsaCipher.init(Cipher.WRAP_MODE, hisPublicKey);
    requestOutputStream.write(rsaCipher.wrap(myDhPublicKey));
    
    // Creates an AES cipher using a 256 bits key derived from the DH public key.
    Cipher aesCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    byte[] aesKeyData = getHash(BigIntegers.asUnsignedByteArray(myDhPublicKey.getY()), 256);
    aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKeyData, symmetricAlgorithmName));
    DataOutputStream aesOutputStream = new DataOutputStream(
            new CipherOutputStream(requestOutputStream, aesCipher));
    
    // Creates the timestamp.
    long timestamp = System.currentTimeMillis();
    aesOutputStream.writeLong(timestamp);

    // First 2 bytes of my public key.
    byte[] myPublicKeyShortHash = Arrays.copyOfRange(
            BigIntegers.asUnsignedByteArray(myPublicKey.getPublicExponent()), 0, 2);
    aesOutputStream.write(myPublicKeyShortHash);

    // Create the signature.
    Signature signer = Signature.getInstance(signatureDesc, jceProviderName);
    signer.initSign(myPrivateKey);
    DataOutputStream sos = new DataOutputStream(new SignatureOutputStream(signer));
    sos.write(aesKeyData); // Useful to prevent the signed content to be determinist.
    sos.writeLong(timestamp);
    CryptoUtil.exportPublicKey(hisPublicKey, sos, false);
    sos.close();
    
    aesOutputStream.write(signer.sign());
    aesOutputStream.close();
    
    return requestOutputStream.toByteArray();
  }

  public void handleConnectionAnswer(byte[] answerData)
          throws InvalidMessage {
  }

}
