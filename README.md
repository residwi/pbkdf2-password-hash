# Simple `PBKDF2` Password Hashing

Hash password using `PBKDF2WithHmacSHA256` algorithm and `27500` iterations.

## Usage

### Hash Password

`Pbkdf2Password.hash()` return `CredentialModel` to get hashed password and salt, so you can store it in
database.

```java
CredentialModel credentialModel = Pbkdf2Password.hash("yourPassword");
```

### Verify Password

You can verify hashed password against a plain text password.

```java
CredentialModel credentialModel = new CredentialModel("hashPasswordFromDatabase", "saltFromDatabase");

boolean isVerified = Pbkdf2Password.verify("yourPassword", credentialModel);
```