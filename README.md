# Stack Activity 2 - Security

- [Salt and Hashing](#salt-and-hashing)
- [JSON Web Tokens](#json-web-tokens)
- [Instant and Duration](#instant-and-duration)


## Salt and Hashing

### Generating a Random Salt

We create a random salt by first creating a instance of `SecureRandom` to ensure that our bytes are truly random for a secuirty context. We then create a empty byte array and pass this into `SecureRandom::nextBytes(byte[] bytes)` function to *fill* the byte array with random bytes.

```java
SecureRandom secureRandom = new SecureRandom();

public byte[] generateSalt()
{
    byte[] salt = new byte[4];     

    secureRandom.nextBytes(salt);

    return salt;
}
```

### Hashing a users Password

We use Java's `SecretKeyFactory` to help with hashing. We first create an instance by giving it our `HASH_FUNCTION`. WE then specify our `PBEKeySpec` by passing in our: `password`, `salt`, `ITERATIONS`, and `KEY_BIT_LENGTH`. We then pass this into the `SecretKeyFactory::generateSecret(PBEKeySpec keySpec)` function giving us a a `SecretKey` instance. This contains our salt+hashed password that is safe to store in our database. Use the `SecretKey::getEncoded()` function to get our byte array and encode it, as well as our salt, into a base64 String using Java's `Base64`.

**Note:** The `HASH_FUNCTION`, `ITERATIONS`, and `KEY_BIT_LENGTH` are constant values provided to you.

```java
SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

char[] password = "SuperSecretPassword".toCharArray();
byte[] salt = generateSalt(); // From the example above

PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

SecretKey key = skf.generateSecret(spec);

byte[] encodedPassword = key.getEncoded();

String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(encodedPassword);
String base64EncodedHashedSalt = Base64.getEncoder().encodeToString(salt);
```

### Verifying a users password with the stored password

To verify a user, repeat the steps above with the users **Stored Salt** and their **Given Password**. If the resulting **Hashed Password** equals the stored **Hashed Password** then they have given a valid password. If not then their password is not correct and return the appropriate response.

## JSON Web Tokens

A JSON Web Token is created by first creating a `JWTClaimsSet` and `JWSHeader` combining them into `SignedJWT`, and then `signing` the resulting `SignedJWT`

### Creating a JWTClaimsSet

A claim set is the claims we want to declare about the given user. For this project we want to make claims about the users: email, id, roles, as well as set the issueTime and expirationTime.

```java
JWTClaimsSet claimsSet =
    new JWTClaimsSet.Builder()
        .subject(email)
        .expirationTime(expireTime)
        .claim(JWTManager.CLAIM_ID, userId)    // we set claims like values in a map
        .claim(JWTManager.CLAIM_ROLES, roles)
        .issueTime(Date.from(Instant.now()))
        .build();
```


### Creating a JWSHeader

When we create out header we will be using the constants found in the provided `JWTManager` class as well as attaching our `EcKey`'s id to it.

```java
JWSHeader header =
    new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
        .keyID(manager.getEcKey().getKeyID())
        .type(JWTManager.JWS_TYPE)
        .build();
```

### Creating a SignedJWT and signing it

Once we have our `JWSHeader` and `JWTClaimsSet` we can create a `SignedJWT` and sign it using the provided `JWTManager`.

```java
SignedJWT signedJWT = new SignedJWT(header, claimsSet);
signedJWT.sign(manager.getSigner());
```

### Verifying a SignedJWT

We can verify if a `SignedJWT` was created by us and that it has not been modified by using the provided `JWTManager`. 

```java
try {
    // Rebuild the SignedJWT from the serialized String
    SignedJWT signedJWT = SignedJWT.parse(serialized);
    
    signedJWT.verify(manager.getVerifier());
    manager.getJwtProcessor().process(signedJWT, null);

    // Do logic to check if expired manually
    signedJWT.getJWTClaimsSet().getExpirationTime();

} catch (IllegalStateException | JOSEException | BadJOSEException | ParseException e) {
    LOG.error("This is not a real token, DO NOT TRUST");
    e.printStackTrace();
    // If the verify function throws an error that we know the
    // token can not be trusted and the request should not be continued
}
```

## Instant and Duration

### Instant

In Java the best way to deal with time is using the `Instant` class. This class has some convient functions for creating the current time, comparing times, and adding times.

Getting a new instant of the current time:
```java
Instant currentTime = Instant.now;
```

Comparing two times:
```java
Instant expireTime = getExpireTime();

if (Instant.now().isAfter(expireTime)) {
    // The current time is AFTER the expire time
} 
```


### Duration

In Java we use the `Duration` class to keep a specific "Time Duration".

You can create a `Duration` by using the static builders in `Duration`
```java
Duration expire = Duration.ofHours(2); // Much more readable then using EPOCH
```

Adding a Duration to Instant
```java
Instant currentTime = Instant.now();
Duration expireDuration = Duration.ofHours(2);

Instant expireTime = currentTime.plus(expireDuration);
```

