package com.residwi.pbkdf2password;

import com.residwi.pbkdf2password.model.CredentialModel;
import com.residwi.pbkdf2password.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Pbkdf2Password {

    private static final int DEFAULT_ITERATIONS = 27500;
    private static final String DEFAULT_PBKDF2ALGORITHM = "PBKDF2WithHmacSHA256";

    private Pbkdf2Password() {
    }

    public static boolean verify(String rawPassword, CredentialModel credentialModel) {
        return encodedCredential(rawPassword, DEFAULT_ITERATIONS, credentialModel.getSalt(), keySize(credentialModel))
                .equals(credentialModel.getPassword());
    }

    public static CredentialModel hash(String rawPassword) {
        String salt = Base64.encodeBytes(getSalt());
        String passwordHash = encodedCredential(rawPassword, DEFAULT_ITERATIONS, salt, 512);

        return new CredentialModel(passwordHash, salt);
    }

    private static int keySize(CredentialModel credential) {
        try {
            byte[] bytes = Base64.decode(credential.getPassword());
            return bytes.length * 8;
        } catch (IOException e) {
            throw new RuntimeException("Credential could not be decoded", e);
        }
    }

    private static String encodedCredential(String rawPassword, int iterations, String salt, int derivedKeySize) {
        try {
            KeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), Base64.decode(salt), iterations, derivedKeySize);
            byte[] key = getSecretKeyFactory().generateSecret(spec).getEncoded();

            return Base64.encodeBytes(key);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Credential could not be encoded", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }

    private static SecretKeyFactory getSecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance(DEFAULT_PBKDF2ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("PBKDF2 algorithm not found", e);
        }
    }
}
