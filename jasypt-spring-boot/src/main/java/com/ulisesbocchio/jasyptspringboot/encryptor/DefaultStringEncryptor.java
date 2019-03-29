package com.ulisesbocchio.jasyptspringboot.encryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class DefaultStringEncryptor implements StringEncryptor {

    private SecretKey key;
    private int saltSize;
    private int iterations;


    public DefaultStringEncryptor(String algorithm, String password, int saltSize, int iterations) throws Exception{
        key = SecretKeyFactory.getInstance(algorithm).generateSecret(new PBEKeySpec(password.toCharArray()));
        this.iterations = iterations;
        this.saltSize = saltSize;


    }

    @Override
    public String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        byte[] salt = generateRandom(saltSize);
        cipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterations));
        byte[] utf8 = message.getBytes("UTF-8");
        byte[] enc = cipher.doFinal(utf8);
        return Base64.getEncoder().encodeToString(combineArray(salt, enc));
    }

    @Override
    public String decrypt(String message) throws Exception {

        byte[] dec = Base64.getDecoder().decode(message);

        byte[] salt = splitLeft(dec, saltSize);
        byte[] enc = splitRight(dec, saltSize);

        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterations));

        byte[] utf8 = cipher.doFinal(enc);
        return new String(utf8, "UTF8");
    }

    public static byte[] generateRandom(int blockSize) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[blockSize];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] combineArray(byte[] one, byte[] two) {
        byte[] combined = new byte[one.length + two.length];
        System.arraycopy(one, 0, combined, 0, one.length);
        System.arraycopy(two, 0, combined, one.length, two.length);
        return combined;
    }

    public static byte[] splitLeft(byte[] payload, int size) {
        byte[] left = new byte[size];
        System.arraycopy(payload, 0, left, 0, left.length);
        return left;
    }

    public static byte[] splitRight(byte[] payload, int size) {
        byte[] right = new byte[payload.length - size];
        System.arraycopy(payload, size, right, 0, right.length);
        return right;
    }

    public static void main(String[] args)  throws  Exception{
        DefaultStringEncryptor defaultStringEncryptor = new DefaultStringEncryptor("PBEWithMD5AndDES", "passphrase", 8,20);
        System.out.println("Encrypting: 'mypassword'");
        String encrypt = defaultStringEncryptor.encrypt("mypassword");
        System.out.println("encrypted: "+encrypt);
        String decrypt = defaultStringEncryptor.decrypt(encrypt);
        System.out.println("decrypted: "+ decrypt);
    }

}
