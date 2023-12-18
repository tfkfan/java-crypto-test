package com.tfkfan;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class RsaEncryptor {
    private final static String DEFAULT_ALG = "RSA";
    private final KeyPair keyPair;
    private final Cipher cipher;
    private final Base64.Decoder decoder = Base64.getDecoder();
    private final Base64.Encoder encoder = Base64.getEncoder();

    public RsaEncryptor() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(DEFAULT_ALG);
    }

    public RsaEncryptor(String alg) throws NoSuchAlgorithmException, NoSuchPaddingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(alg);
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.cipher = Cipher.getInstance(alg);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public String encrypt(String data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        return encoder.encodeToString(cipher.doFinal(data.getBytes()));

    }

    public String decrypt(String data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return new String(cipher.doFinal(decoder.decode(data)));
    }
}
