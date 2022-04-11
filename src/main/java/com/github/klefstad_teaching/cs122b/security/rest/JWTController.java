package com.github.klefstad_teaching.cs122b.security.rest;

import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@RestController
public class JWTController
{
    private static final Logger LOG = LoggerFactory.getLogger(JWTController.class);

    private final JWTManager manager;

    public JWTController()
    {
        this.manager = new JWTManager.Builder()
            .accessTokenExpire(Duration.ofDays(1))
            .keyFileName("ec-key.json")
            .maxRefreshTokenLifeTime(Duration.ofDays(1))
            .refreshTokenExpire(Duration.ofDays(1))
            .accessTokenExpire(Duration.ofDays(1))
            .build();
    }

    @GetMapping("/token")
    public ResponseEntity<?> token()
        throws JOSEException, ParseException
    {
        // Here is some basic information we want to add to our accesstoken
        String       email  = "User@examle.com";
        Long         userId = 1L;
        List<String> roles  = Collections.singletonList("Admin");

        // All the information is added in the JWTClaimsSet
        // This also includes when the token was issued and when it expires
        JWTClaimsSet claimsSet =
            new JWTClaimsSet.Builder()
                .subject(email)
                .expirationTime(
                    Date.from(
                        Instant.now().plus(this.manager.getAccessTokenExpire())))
                .claim(JWTManager.CLAIM_ID, userId)    // we set claims like values in a map
                .claim(JWTManager.CLAIM_ROLES, roles)
                .issueTime(Date.from(Instant.now()))
                .build();

        // This is the header of the access token that states
        // the Algorithm used to sign the token, the key's id, and the type of JWS
        JWSHeader header =
            new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                .keyID(manager.getEcKey().getKeyID())
                .type(JWTManager.JWS_TYPE)
                .build();

        // We then create out JWT using our header and claimsSet
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        // And finally we sign the token with our manager
        // So that later we can verify if the token was acutally created
        // by us by using the verifier (jwt.verify(manager.getVerifier());)
        signedJWT.sign(manager.getSigner());

        // When we pass our access token around in our services we use the
        // serialized form, with is a base 64 encoded string representation of the jwt
        String serialized = signedJWT.serialize();

        LOG.info("\nHeader: {}\nPayload: {}\nSignature: {}",
                 signedJWT.getHeader().toJSONObject(),
                 signedJWT.getPayload().toJSONObject(),
                 signedJWT.getSignature());

        LOG.info("\nSerialized:\n{}", serialized);

        // Now when we get a jwt we can verify that the token has not been modified and that
        // we were the ones that issued and signed it by using our verifier

        try {
            SignedJWT rebuiltSignedJwt = SignedJWT.parse(serialized);

            rebuiltSignedJwt.verify(manager.getVerifier());
            manager.getJwtProcessor().process(rebuiltSignedJwt, null);

            // Do logic to check if expired manually
            rebuiltSignedJwt.getJWTClaimsSet().getExpirationTime();

        } catch (IllegalStateException | JOSEException | BadJOSEException e) {
            LOG.error("This is not a real token, DO NOT TRUST");
            e.printStackTrace();
            // If the verify function throws an error that we know the
            // token can not be trusted and the request should not be continued
        }

        LOG.info("Since signedJWT.verify() did not throw an error we can trust this token!");

        return ResponseEntity.ok().build();
    }
}
