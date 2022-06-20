package com.gitcodings.stack.security.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@RestController
public class HashAndSaltedController
{
    private static final Logger LOG = LoggerFactory.getLogger(HashAndSaltedController.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    @GetMapping("/hash")
    public ResponseEntity<?> hash()
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

        // Our Password in char[] format
        char[] password = "SuperSecretPassword".toCharArray();

        // Our salt, that has been filled with random bytes
        byte[] salt     = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt); // Insures that the bytes are truly random

        LOG.info("Password: {}, salt: {}",  password, salt);

        // Our key spec
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

        // Our salt and hashed password
        SecretKey key = skf.generateSecret(spec);

        byte[] encoded = key.getEncoded();

        String base64Encoded = Base64.getEncoder().encodeToString(encoded);

        LOG.info("Hashed + Salted Password: {}",  base64Encoded);

        // Now to verify if a given password matches our salt

        char[] correctPassword = "SuperSecretPassword".toCharArray();
        char[] incorrectPassword = "NotMyPassword".toCharArray();

        // Notice how we use the same salt as before
        // When we want to verify if the password given to us matches the stored
        // hashed and salted password we must use the same salt that we used
        // when we first hashed and salted the password
        PBEKeySpec specWithCorrectPass =
            new PBEKeySpec(correctPassword, salt, ITERATIONS, KEY_BIT_LENGTH);
        PBEKeySpec specWithWrongPass =
            new PBEKeySpec(incorrectPassword, salt, ITERATIONS, KEY_BIT_LENGTH);

        SecretKey keyWithCorrectPass = skf.generateSecret(specWithCorrectPass);
        SecretKey keyWithWrongPass = skf.generateSecret(specWithWrongPass);

        byte[] encodedCorrectPass = keyWithCorrectPass.getEncoded();
        byte[] encodedWrongPass = keyWithWrongPass.getEncoded();

        String base64EncodedCorrectPass = Base64.getEncoder().encodeToString(encodedCorrectPass);
        String base64EncodedWrongPass = Base64.getEncoder().encodeToString(encodedWrongPass);

        LOG.info("Correct Pass Hash: {}",  base64EncodedCorrectPass);
        LOG.info("Wrong Pass Hash: {}",  base64EncodedWrongPass);

        // We expect the two hashed passwords to match when the correct password is given
        LOG.info("\n{}\n\t==\n{}\n\t{}", base64EncodedCorrectPass, base64Encoded, base64EncodedCorrectPass.equals(base64Encoded));

        // We expect the two hashed passwords to NOT match when the WRONG password is given
        LOG.info("\n{}\n\t==\n{}\n\t{}", base64EncodedWrongPass, base64Encoded, base64EncodedWrongPass.equals(base64Encoded));

        return ResponseEntity.ok().build();
    }
}
