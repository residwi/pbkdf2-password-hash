package com.residwi.pbkdf2password;

import com.residwi.pbkdf2password.model.CredentialModel;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class Pbkdf2PasswordTest {

    private final static String password = "TeSt123@!";

    @Test
    public void testPasswordHashSuccess() {
        boolean isVerified = Pbkdf2Password.verify(password, hashPassword());

        assertTrue(isVerified);
    }

    @Test
    public void testPasswordHashFailed() {
        boolean isVerified = Pbkdf2Password.verify("wrongPassword", hashPassword());

        assertFalse(isVerified);
    }

    private CredentialModel hashPassword() {
        return Pbkdf2Password.hash(password);
    }
}
