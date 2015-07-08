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
## Protocol
### cipherData object
The cipherData object contains information about the algorithm and encrypted fields in an encrypted json object. It always has the field name `cipherData` and is always found at the root.  
A cipherData object might look like this during processing
``` json
{
	"iv":"9Tp+5f4EU3jbtqZNSg99IA==",
	"cipher":"SHA-256/CTR/NoPadding",
	"fields":{
		"field1":{
			"obfuscatedFieldName":true,
			"digest":"MD5",
			"iv":"qCDIPFhANrnTQrKWqJTTzw=="
		},
		"field2":{
			"obfuscatedFieldName":false,
			"iv":"4Lh7m6YfwAWG8m1VGrT/ag=="
		}
	}
}
```
Or this once encrypted
``` json
{
	"iv":"9Tp+5f4EU3jbtqZNSg99IA==",
	"cipher":"SHA-256/CTR/NoPadding",
	"fields":"BIIZSayIBQvVGp6mJiZllm28DVPJQiuPKrL67ehmq1Dbvrq27q1n7GTNNf97digTfuj1IoMR8YfKFx9hUvBRL6SQq1TxDeB0IvGrJ3aN7TTzSF10R585pidfwHY9wV32u7ZcMuZfbjYSKIiSB/PSdMVg30F08i2lkhdy957bs/I4iNqp3P0IN7rwaqEj+tjKjBhpqzr03ta3JZ7yaRKywQ=="
}
```
#### Fields
##### iv
The `iv` field is a base 64 encoded string containing the initialization vector needed to decrypt the `fields` object.
##### cipher
The `cipher` field is a string containing a cipher transform. https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher.
##### fields
The `fields` object contains field descriptors. In an encrypted json object `fields` will be a base 64 string, but in processing it will be an object with field descriptor objects named corresponding to field names in the encrypted fields map.
##### field descriptor
Field descriptor objects have the following fields
###### iv
A required field. A base 64 string with the iv used to decrypt the field in the root object.
###### obfuscatedFieldName
A required boolean field indicating if the field's name is obfuscated at the top level object.
###### digest
Required if `obfuscatedFieldName` is true. A string containing the name of the digest algorithm used to obfuscate the field name.
