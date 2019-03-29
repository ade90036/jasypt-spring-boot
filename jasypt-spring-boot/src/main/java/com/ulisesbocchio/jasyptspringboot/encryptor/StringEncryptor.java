package com.ulisesbocchio.jasyptspringboot.encryptor;

public interface StringEncryptor {
    String encrypt(String message) throws Exception;
    String decrypt(String message) throws Exception;
}
