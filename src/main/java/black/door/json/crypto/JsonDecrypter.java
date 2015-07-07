package black.door.json.crypto;

import black.door.json.Derulo;
import black.door.json.JsonObject;
import black.door.json.crypto.exceptions.JsonCryptoException;
import black.door.util.DBP;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Created by nfischer on 7/6/15.
 */
public class JsonDecrypter implements JsonCrypter {

    private Cipher cipher;
    private Provider cipherProvider;
    private Key key;
    private JsonObject cipherJson;
    private Provider digestProvider;

    public JsonDecrypter(Key key, Provider cipherProvider) {
        this.cipherProvider = cipherProvider;
        this.key = key;
    }

    public JsonDecrypter(Key key) {
        this.key = key;
    }

    /**
     * @return the Provider that this object will use when obtaining digest instances for field obfuscation
     */
    public Provider getDigestProvider() {
        return digestProvider;
    }

    /**
     * @param digestProvider the Provider that this object will use when obtaining digest instances for field obfuscation. null will cause this object to use default system providers
     */
    public void setDigestProvider(Provider digestProvider) {
        this.digestProvider = digestProvider;
    }

    public Provider getCipherProvider() {
        return cipherProvider;
    }

    public void setCipherProvider(Provider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    public void setCipherJson(String json) {
        setCipherJson(new JsonObject(json));
    }

    @Override
    public Cipher getCipher() {
        return cipher;
    }

    @Override
    public String getPlainJson() throws JsonCryptoException {
        return Derulo.toJSON(getPlainJsonObject());
    }

    public JsonObject getPlainJsonObject() throws JsonCryptoException {
        JsonObject plainJson;
        JsonObject cipherJson = new JsonObject();
        String transform;
        JsonObject cipherData;

        cipherJson.putAll(this.cipherJson);

        if (this.cipherJson == null)
            throw new JsonCryptoException("Encrypted json object 'cipherJson' is not set.");

        JsonObject temp = this.cipherJson.getJsonObject("cipherData");
        if (temp == null)
            throw new JsonCryptoException("'cipherData' object in encrypted json object is missing or not an object.");
        cipherData = new JsonObject();
        cipherData.putAll(temp);

        transform = cipherData.getString("cipher");
        if (transform == null)
            throw new JsonCryptoException("field 'cipher' in 'cipherData' object is missing or not a string.");

        try {
            if (cipherProvider == null) {
                cipher = Cipher.getInstance(transform);
            } else {
                cipher = Cipher.getInstance(transform, cipherProvider);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            DBP.printException(e);
            throw new JsonCryptoException("Unable to get a cipher instance from transform specified in cipherJson object " + e.getMessage());
        }

        try {
            String tlivString = cipherData.getString("iv");//top level iv string
            if (tlivString == null)
                throw new JsonCryptoException("'iv' field in 'cipherData' object is missing or not a string.");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(tlivString)));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            DBP.printException(e);
            throw new JsonCryptoException("could not initialize cipher with given key or iv " + e.getMessage());
        }

        try {
            String fieldsString = cipherData.getString("fields");
            if (fieldsString == null)
                throw new JsonCryptoException("'fields' field in 'cipherData' object is missing or not a string.");
            byte[] fieldsBytes = Base64.getDecoder().decode(fieldsString);
            cipherData.put("fields", Derulo.fromJSON(new String(cipher.doFinal(fieldsBytes), StandardCharsets.UTF_8)));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            DBP.printException(e);
            throw new JsonCryptoException("Could not decrypt 'fields' in 'cipherData " + e.getMessage());
        }

        plainJson = new JsonObject();

        JsonObject fieldDescriptors = cipherData.getJsonObject("fields");
        try {
            for (String realFieldName : fieldDescriptors.keySet()) {
                JsonObject data = fieldDescriptors.getJsonObject(realFieldName);
                String fieldName = realFieldName;
                if (data == null)
                    throw new JsonCryptoException("field info for " + realFieldName + " is not a json object.");
                Boolean obfuscated = data.getBoolean("obfuscatedFieldName");
                if (obfuscated != null && obfuscated) {
                    String digestName = data.getString("digest");
                    if (digestName == null)
                        throw new JsonCryptoException(realFieldName + " is marked as having an obfuscated field name but no 'digest' field is defined in cipherData.fields." + realFieldName);
                    MessageDigest digest;
                    try {
                        if (digestProvider == null) {
                            digest = MessageDigest.getInstance(digestName);

                        } else {
                            digest = MessageDigest.getInstance(digestName, digestProvider);
                        }
                    } catch (NoSuchAlgorithmException e) {
                        DBP.printException(e);
                        throw new JsonCryptoException("Could not find a digest with the name " + digestName);
                    }

                    fieldName = Base64.getEncoder().encodeToString(digest.digest(realFieldName.getBytes(StandardCharsets.UTF_8)));
                }

                Cipher fieldCipher;
                if (cipherProvider == null) {
                    fieldCipher = Cipher.getInstance(transform);
                } else {
                    fieldCipher = Cipher.getInstance(transform, cipherProvider);
                }

                String fieldIv = data.getString("iv");

                if (fieldIv == null) {
                    throw new JsonCryptoException("'iv' field for " + realFieldName + " not found.");
                }

                fieldCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(fieldIv)));

                String cipherFieldString = cipherJson.getString(fieldName);
                if (cipherFieldString == null) {
                    throw new JsonCryptoException("Could not find encrypted field " + realFieldName + " with name " + fieldName);
                }
                byte[] cipherFieldBytes = Base64.getDecoder().decode(cipherFieldString);
                String clearFieldString = new String(fieldCipher.doFinal(cipherFieldBytes), StandardCharsets.UTF_8);

                plainJson.put(realFieldName, Derulo.fromJSON(clearFieldString));
                cipherJson.remove(fieldName);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            DBP.printException(e);
            throw new JsonCryptoException("Could not decrypt a field '" + e.getMessage() + "'");
        }

        cipherJson.remove("cipherData");

        plainJson.putAll(cipherJson);

        return plainJson;
    }

    @Override
    public String getCipherJson() {
        return Derulo.toJSON(cipherJson);
    }

    public void setCipherJson(JsonObject json) {
        this.cipherJson = json;
    }
}
