package com.residwi.pbkdf2password.model;

public class CredentialModel {

    private String password;

    private String salt;

    public CredentialModel(String password, String salt) {
        this.password = password;
        this.salt = salt;
    }

    public String getPassword() {
        return password;
    }

    public String getSalt() {
        return salt;
    }
}
