package black.door.json.crypto.exceptions;

/**
 * Created by nfischer on 7/6/15.
 */
public class JsonCryptoException extends RuntimeException{
    public JsonCryptoException(String s){
        super(s);
    }
    public JsonCryptoException(){
        super();
    }
}
