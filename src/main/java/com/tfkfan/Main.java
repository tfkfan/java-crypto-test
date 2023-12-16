package com.tfkfan;


public class Main {

    public static void main(String[] args) throws Exception {
        String messageToSign = "This is a message to sign";
        SignatureProcessor s = new SignatureProcessor(messageToSign);
        SignatureProcessor s2 = new SignatureProcessor(messageToSign.concat("AAA"));
        String signature = s.signature();

        System.out.println("Digital Signature....");
        System.out.printf("Message: \"%s\", signature: \"%s\", verified: \"%s\", wrong signature: \"%s\"",
                messageToSign, signature,
                s.verify(signature),
                s.verify(s2.signature()));
        System.out.println();
        System.out.println("..................................................");

        String messageToEncrypt = "This is a message to encrypt";
        RsaEncryptor encryptor = new RsaEncryptor();
        String encrypted = encryptor.encrypt(messageToEncrypt);
        System.out.println("Rsa encryption....");
        System.out.printf("Message: \"%s\", encrypted: \"%s\", decrypted: \"%s\"%n", messageToEncrypt,
                encrypted,
                encryptor.decrypt(encrypted));
        System.out.println();
        System.out.println("..................................................");
    }
}