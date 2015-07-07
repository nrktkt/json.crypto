package black.door.json.crypto;

import black.door.json.Derulo;
import black.door.json.JsonObject;
import black.door.json.crypto.exceptions.JsonCryptoException;
import black.door.util.DBP;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Map;

/**
 * Created by nfischer on 7/6/15.
 */
public class JsonEncrypter implements JsonCrypter {
    private Cipher cipher;
    private JsonObject plainJson;
    private MessageDigest digest;
    private Map<String, Boolean> encryptedFields;
    private Key key;

    /**
     * @param key            the encryption key to use for encryption
     * @param transformation the name of the transformation, e.g., DES/CBC/PKCS5Padding. See the Cipher section in the Java Cryptography Architecture Standard Algorithm Name Documentation for information about standard transformation names.
     * @param provider
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public JsonEncrypter(Key key, String transformation, Provider provider) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        cipher = Cipher.getInstance(transformation, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        this.key = key;
    }

    /**
     * @param key            the encryption key to use for encryption
     * @param transformation the name of the transformation, e.g., DES/CBC/PKCS5Padding. See the Cipher section in the Java Cryptography Architecture Standard Algorithm Name Documentation for information about standard transformation names.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public JsonEncrypter(Key key, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        this.key = key;
    }

    /**
     * @return a map from names of fields that will be encrypted to booleans indicating if those field names will be obfuscated in the json ciphertext
     */
    public Map<String, Boolean> getEncryptedFields() {
        return encryptedFields;
    }

    /**
     * Tells the encryptor which fields should be encrypted and if their name should be obfuscated.
     * Keys in the encryptedFields map should be field names. Any field name appearing as a key will be encrypted.
     * Values in the encryptedFields map indicate if the corresponding key should be obfuscated. Field names will be obfuscated by hashing using the digest manipulated by setDigest and getDigest
     *
     * @param encryptedFields
     */
    public void setEncryptedFields(Map<String, Boolean> encryptedFields) {
        this.encryptedFields = encryptedFields;
    }

    public MessageDigest getDigest() {
        return digest;
    }

    public void setDigest(MessageDigest digest) {
        this.digest = digest;
    }

    public Cipher getCipher() {
        return cipher;
    }

    public String getPlainJson() {
        return plainJson.toJSONString();
    }

    public void setPlainJson(String jsonText) {
        this.plainJson = new JsonObject(jsonText);
    }

    public void setPlainJson(JsonObject jsonObject) {
        this.plainJson = jsonObject;
    }

    private JsonObject getNewCipherDataTemplate() {
        JsonObject cipherData = new JsonObject();
        cipherData.put("iv", Base64.getEncoder().encodeToString(cipher.getIV()));
        cipherData.put("cipher", cipher.getAlgorithm());
        return cipherData;
    }

    private JsonObject getFieldsDescriptors() {
        JsonObject fields = new JsonObject();
        for (Map.Entry<String, Boolean> entry : encryptedFields.entrySet()) {
            JsonObject field = new JsonObject();
            if (entry.getValue()) {
                field.put("obfuscatedFieldName", true);
                field.put("digest", digest.getAlgorithm());
            } else {
                field.put("obfuscatedFieldName", false);
            }
            fields.put(entry.getKey(), field);
        }
        return fields;
    }

    public String getCipherJson() {
        try {
            return Derulo.toJSON(getCipherJsonObject());
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            DBP.printException(e);
            throw new JsonCryptoException("Could not encrypt something: " + e.getMessage());
        }
    }

    public JsonObject getCipherJsonObject() throws BadPaddingException, IllegalBlockSizeException {
        JsonObject plainJson = new JsonObject();
        plainJson.putAll(this.plainJson);
        JsonObject cipherJson = new JsonObject();

        JsonObject fields = getFieldsDescriptors();

        for (Map.Entry<String, Boolean> entry : encryptedFields.entrySet()) {
            Object fieldValue = plainJson.get(entry.getKey());
            if (fieldValue == null) {
                throw new JsonCryptoException(entry.getKey() + " was specified to be encrypted, but was not found in plain json");
            }

            String fieldName = entry.getKey();
            if (entry.getValue()) {
                digest.reset();
                fieldName = Base64.getEncoder().encodeToString(digest.digest(fieldName.getBytes(StandardCharsets.UTF_8)));
            }

            try {
                Cipher fieldCipher = Cipher.getInstance(cipher.getAlgorithm(), cipher.getProvider());
                fieldCipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] fieldBytes = Derulo.toJSON(fieldValue).getBytes(StandardCharsets.UTF_8);
                byte[] fieldCipherBytes = fieldCipher.doFinal(fieldBytes);
                cipherJson.put(fieldName, Base64.getEncoder().encodeToString(fieldCipherBytes));

                ((JsonObject) fields.get(entry.getKey())).put("iv", Base64.getEncoder().encodeToString(fieldCipher.getIV()));

                plainJson.remove(entry.getKey());

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                DBP.printException(e);
                throw new RuntimeException("Could not initialize cipher for some reason " + e.getMessage()); //TODO
            }
        }

        cipherJson.putAll(plainJson);

        JsonObject cipherData = getNewCipherDataTemplate();

        cipher.doFinal();
        byte[] cipherFields = cipher.doFinal(Derulo.toJSON(fields).getBytes(StandardCharsets.UTF_8));

        cipherData.put("fields", Base64.getEncoder().encodeToString(cipherFields));
        cipherJson.put("cipherData", cipherData);

        return cipherJson;
    }
}
