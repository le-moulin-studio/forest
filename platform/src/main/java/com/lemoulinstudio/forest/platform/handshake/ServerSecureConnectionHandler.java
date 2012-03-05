package com.lemoulinstudio.forest.platform.handshake;

import com.lemoulinstudio.forest.platform.crypto.CryptoUtil;
import com.lemoulinstudio.forest.platform.crypto.SignatureOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.BigIntegers;

public class ServerSecureConnectionHandler extends SecureConnectionHandler {
  
  private Set<PublicKey> contactsPublicKey;
  
  public ServerSecureConnectionHandler(KeyPair ownKeyPair,
                                       Set<PublicKey> contactsPublicKey) {
    this(ownKeyPair, contactsPublicKey, new SecureRandom());
  }

  public ServerSecureConnectionHandler(KeyPair ownKeyPair,
                                       Set<PublicKey> contactsPublicKey,
                                       SecureRandom secureRandom) {
    super(ownKeyPair, secureRandom);
    this.contactsPublicKey = contactsPublicKey;
  }

  public byte[] handleConnectionRequest(byte[] requestData)
          throws Exception {
    // Reads the wrapped key.
    byte[] wrappedKey = Arrays.copyOfRange(requestData, 0, 4096 / 8);
    
    // Unwraps it.
    Cipher requestRsaCipher = Cipher.getInstance(asymmetricCipherDesc, jceProviderName);
    requestRsaCipher.init(Cipher.UNWRAP_MODE, myPrivateKey);
    hisDhPublicKey = (DHPublicKey) requestRsaCipher.unwrap(wrappedKey, "DH", Cipher.PUBLIC_KEY);
    
    // Creates an AES cipher using a 256 bits key derived from the DH public key.
    Cipher requestAesCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    byte[] hisDhPublicKeyData = BigIntegers.asUnsignedByteArray(hisDhPublicKey.getY());
    byte[] requestAesKeyData = getHash(hisDhPublicKeyData, 256);
    byte[] requestInitialVector = getHash(hisDhPublicKeyData, 128);
    requestAesCipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(requestAesKeyData, symmetricAlgorithmName),
            new IvParameterSpec(requestInitialVector));
    
    // Reads the encrypted aes block.
    byte[] requestEncryptedAesBlock = Arrays.copyOfRange(requestData, 4096 / 8, requestData.length);
    
    // Decrypts it.
    byte[] requestDecryptedAesBlock = requestAesCipher.doFinal(requestEncryptedAesBlock);
    
    DataInputStream aesInputStream = new DataInputStream(new ByteArrayInputStream(requestDecryptedAesBlock));
    
    // Reads the timestamp.
    long hisTimestamp = aesInputStream.readLong();
    
    // First 2 bytes of his public key.
    byte[] hisPublicKeyShortHash = new byte[2];
    aesInputStream.readFully(hisPublicKeyShortHash);
    
    // Reads the signature.
    byte[] hisSignature = new byte[4096 / 8];
    aesInputStream.readFully(hisSignature);
    
    // Ignores the remaining data, if any.
    aesInputStream.close();

    // If the timestamps are separated by more than 5 minutes, invalid.
    long myTimeStamp = System.currentTimeMillis();
    if (Math.abs(myTimeStamp - hisTimestamp) > 5 * 60 * 1000) {
      throw new InvalidMessage();
    }
    
    // Find candidates for the origin of the message.
    for (RSAPublicKey candidatePublicKey : findPublicKeyCandidates(hisPublicKeyShortHash)) {
      // Verify the signature for this candidate.
      Signature verifier = Signature.getInstance(signatureDesc, jceProviderName);
      verifier.initVerify(candidatePublicKey);
      DataOutputStream dos = new DataOutputStream(new SignatureOutputStream(verifier));
      dos.write(requestAesKeyData);
      dos.writeLong(hisTimestamp);
      CryptoUtil.exportPublicKey(myPublicKey, dos, false);
      dos.close();
      if (verifier.verify(hisSignature)) {
        hisPublicKey = candidatePublicKey;
        break;
      }
    }
    
    // If no candidate to identify the source were found, invalid.
    if (hisPublicKey == null) {
      throw new InvalidMessage();
    }
    
    // From here the request is considered valid. We prepare the response.
    ByteArrayOutputStream responseOutputStream = new ByteArrayOutputStream(1024);
    
    // Generates my DH key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", jceProviderName);
    keyPairGenerator.initialize(dhParameterSpec, secureRandom);
    KeyPair dhKeyPair = keyPairGenerator.generateKeyPair();
    myDhPublicKey = (DHPublicKey) dhKeyPair.getPublic();
    myDhPrivateKey = (DHPrivateKey) dhKeyPair.getPrivate();
    
    // We have enough information to compute the shared secret and to derive
    // an encryption cipher and a decryption cipher.
    createCiphersFromSharedSecret();
    
    // Encrypts my DH public key with the hisPublicKey.
    Cipher responseRsaCipher = Cipher.getInstance(asymmetricCipherDesc, jceProviderName);
    responseRsaCipher.init(Cipher.WRAP_MODE, hisPublicKey);
    responseOutputStream.write(responseRsaCipher.wrap(myDhPublicKey));
    
    // Creates an AES cipher using a 256 bits key derived from the DH public key.
    Cipher responseAesCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    byte[] myDhPublicKeyData = BigIntegers.asUnsignedByteArray(myDhPublicKey.getY());
    byte[] responseAesKeyData = getHash(myDhPublicKeyData, 256);
    byte[] responseInitialVector = getHash(myDhPublicKeyData, 128);
    responseAesCipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(responseAesKeyData, symmetricAlgorithmName),
            new IvParameterSpec(responseInitialVector));
    DataOutputStream aesOutputStream = new DataOutputStream(
            new CipherOutputStream(responseOutputStream, responseAesCipher));
    
    // Writes a hash of his signature.
    byte[] hisSignatureHash = getHash(hisSignature, 256);
    aesOutputStream.write(hisSignatureHash);
    
    aesOutputStream.close();
    
    return responseOutputStream.toByteArray();
  }

  // TODO: this part will need to be optimized.
  private List<RSAPublicKey> findPublicKeyCandidates(byte[] publicKeyStart) {
    List<RSAPublicKey> result = new ArrayList<RSAPublicKey>();
    
    keyLoop:
    for (PublicKey contactKey : contactsPublicKey) {
      if (contactKey instanceof RSAPublicKey) {
        RSAPublicKey rsaContactKey = (RSAPublicKey) contactKey;
        byte[] keyData = BigIntegers.asUnsignedByteArray(rsaContactKey.getModulus());
        if (publicKeyStart.length > keyData.length) continue;
        for (int i = 0; i < publicKeyStart.length; i++) {
          if (publicKeyStart[i] != keyData[i]) {
            continue keyLoop;
          }
        }
        result.add(rsaContactKey);
      }
    }
    
    return result;
  }
  
}
