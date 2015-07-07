package black.door.json.crypto;

import javax.crypto.Cipher;

/**
 * Created by nfischer on 7/6/15.
 */
public interface JsonCrypter {
    /**
     *
     * @return the cipher used by this object, or null if a cipher has not been set.
     */
    public Cipher getCipher();

    /**
     * Set json plaintext for this crypter to encrypt
     * @param json a json object
     */
    public default void setPlainJson(String json){
        throw new UnsupportedOperationException();
    }

    /**
     * Set json ciphertext for this crypter to decrypt
     * @param json
     */
    public default void setCipherJson(String json){
        throw new UnsupportedOperationException();
    }

    /**
     *
     * @return the plaintext of the json object this crypter is working on
     */
    public String getPlainJson();

    /**
     *
     * @return the ciphertext of the json object this crypter is working on
     */
    public String getCipherJson();
}
