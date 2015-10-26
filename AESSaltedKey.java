package com.anz.csp.fiat.util;

/**
 * Created by neloshaiker on 25/10/15.
 */
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

/**
 * Created by neloshaiker on 25/10/15.
 */
public class AESSaltedKey {

    /* Notes:
     * initialVector must be set during the encryption pass to ensure decryption
     */
    private byte[] initialVector;
    private byte[] secretKey;
    private String password;
    private String salt;
    private int pswdIterations;
    private int keySize;


    public AESSaltedKey(String password, int pswdIterations, int keySize) throws Exception {

        this.salt = generateSalt();
        this.password = password;
        this.pswdIterations = pswdIterations;
        this.keySize = keySize;
        byte[] saltBytes = salt.getBytes("UTF-8");

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                saltBytes,
                pswdIterations,
                keySize
        );

        SecretKey secretKeyFactory = factory.generateSecret(spec);
        secretKey = secretKeyFactory.getEncoded();

    }


    public byte[] getInitialVector() {
        return initialVector;
    }

    public void setInitialVector(byte[] initialVector) {
        this.initialVector = initialVector;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public String getPassword() {
        return password;
    }

    public String getSalt() {
        return salt;
    }

    public int getPswdIterations() {
        return pswdIterations;
    }

    public int getKeySize() {
        return keySize;
    }

    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        String s = new String(bytes);
        return s;
    }

}
