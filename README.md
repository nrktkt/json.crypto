# json.crypto
The json crypto library offers the ability to encrypt specific fields of a json object. Cipher json objects are still fully compliant json objects, but with additional fields containing encrypted information.
## Encrypting json objects
### Preparing the crypter
#### Create JsonEncrypter Object
Use the constructor of JsonEncrypter the same way you would use Cipher.getInstance.  
For example:
``` java
Key key = new SecretKeySpec(new byte[16], "AES"); // this is a null key, obviously don't do that, use a CSPRNG or PBKDF or scrypt for your key
JsonEncrypter eCrypter = new JsonEncrypter(key, "AES/CTR/NoPadding");
```
#### Set fields to encrypt
Configure which fields of your json object should be encrypted by creating a Map<String, Boolean>. Keys in the map should be field names in the json object. Values in the map indicate whether the field name should be obfuscated upon encryption.

    eCrypter.setEncryptedFields(map);
##### Set MessageDigest for Obfuscation
If any of the entries in the encrypted fields map had a value of `true` then you will need to set a digest.
``` java
eCrypter.setDigest(MessageDigest.getInstance("MD5"));
```
### Encrypt objects
Set the plaintext of object you wish to encrypt.

    eCrypter.setPlainJson(someJsonObjectString);
Get the encrypted object.

    String encryptedJson = eCrypter.getCipherJson();
The crypter should now be ready for encrypting more objects of similar schema with more calls to setPlainJson and getCipherJson
## Decrypting json objects
Decrypting is much easier than encrypting.  
Simply create a JsonDecrypter with a key
``` java
JsonDecrypter dCrypter = new JsonDecrypter(key);
```
Add the json ciphertext

    dCrypter.setCipherJson(someCipherJsonObjectString);
Get the original decrypted json object

    String originalJsonObjectString = dCrypter.getPlainJson();
