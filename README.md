# CS122B Activity 2 - Security

- [Salt and Hashing](#salt-and-hashing)
- [JSON Web Tokens](#json-web-tokens)


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

We use Java's `SecretKeyFactory` to help with hashing. We first create an instance by giving it our `HASH_FUNCTION`. WE then specify our `PBEKeySpec` by passing in our: `password`, `salt`, `ITERATIONS`, and `KEY_BIT_LENGTH`. We then pass this into the `SecretKeyFactory::generateSecret(PBEKeySpec keySpec)` fucntion giving us a a `SecretKey` instance. This contains our salt+hashed password that is safe to store in our database. Use the `SecretKey::getEncoded()` function to get our byte array and encode it, as well as our salt, into a base64 String using Java's `Base64`.

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
