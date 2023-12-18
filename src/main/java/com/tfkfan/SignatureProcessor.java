package com.tfkfan;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SignatureProcessor {
    private final static String DEFAULT_ALG = "RSA";
    private final static String DEFAULT_HASH_ALG = "SHA-256";
    private final String dataToSign;
    private final Cipher cipher;

    private final KeyPair keyPair;
    private final Base64.Decoder decoder = Base64.getDecoder();
    private final Base64.Encoder encoder = Base64.getEncoder();
    private final MessageDigest md = MessageDigest.getInstance(DEFAULT_HASH_ALG);

    public SignatureProcessor(String dataToSign) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(dataToSign, DEFAULT_ALG);
    }

    public SignatureProcessor(String dataToSign, String alg) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.dataToSign = dataToSign;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(alg);
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.cipher = Cipher.getInstance(alg);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public String signature() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return encoder.encodeToString(cipher.doFinal(md.digest(dataToSign.getBytes(StandardCharsets.UTF_8))));
    }

    public boolean verify(String signature) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            return Arrays.equals(md.digest(dataToSign.getBytes(StandardCharsets.UTF_8)),
                    cipher.doFinal(decoder.decode(signature)));
        } catch (Exception e) {
            return false;
        }
    }
}
