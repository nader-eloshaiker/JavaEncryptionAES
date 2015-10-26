package com.anz.csp.fiat.util;

/**
 * Created by neloshaiker on 23/10/15.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.AlgorithmParameters;

public class AESEncryption {

    public static String encrypt(AESSaltedKey keySpec, String plainText) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(keySpec.getSecretKey(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        AlgorithmParameters params = cipher.getParameters();
        keySpec.setInitialVector(params.getParameterSpec(IvParameterSpec.class).getIV());

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedString = DatatypeConverter.printBase64Binary(encryptedBytes);

        return encryptedString;
    }

    public static String decrypt(AESSaltedKey keySpec, String encryptedText) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(keySpec.getSecretKey(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(keySpec.getInitialVector()));


        byte[] decryptedTextBytes = null;
        byte[] encryptedTextBytes = DatatypeConverter.parseBase64Binary(encryptedText);

        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        String decryptedText = new String(decryptedTextBytes);

        return  decryptedText;
    }



    public static String encrypt(String key, String password, String plainText) throws Exception {

        IvParameterSpec intialVector = new IvParameterSpec(password.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, intialVector);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        String encryptedString = DatatypeConverter.printBase64Binary(encryptedBytes);

        return encryptedString;
    }

    public static String decrypt(String key, String password, String encryptedText) throws Exception {

        IvParameterSpec intialVector = new IvParameterSpec(password.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, intialVector);

        byte[] encryptedTextBytes = DatatypeConverter.parseBase64Binary(encryptedText);
        byte[] decryptedTextBytes = null;

        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        String plainText = new String(decryptedTextBytes);

        return plainText;
    }



    public static String encrypt(String key, String plainText) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        String encryptedString = DatatypeConverter.printBase64Binary(encryptedBytes);

        return encryptedString;
    }

    public static String decrypt(String key, String encryptedText) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] encryptedTextBytes = DatatypeConverter.parseBase64Binary(encryptedText);
        byte[] decryptedTextBytes = null;

        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        String plainText = new String(decryptedTextBytes);

        return plainText;
    }
}
