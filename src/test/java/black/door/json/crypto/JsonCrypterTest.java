package black.door.json.crypto;

import black.door.json.Derulo;
import black.door.json.JsonNull;
import black.door.json.JsonObject;

import black.door.util.DBP;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * Created by nfischer on 7/6/15.
 */
public class JsonCrypterTest {

    Map<String, Object> map;
    Map<String, Object> simpleMap;
    List<Object> simpleList;

    @Before
    public void setup(){
        DBP.toggleVerbose();

        map = new HashMap<>();

        simpleMap = new HashMap<>();
        simpleMap.put("string", "sample");
        simpleMap.put("int", 5l);
        simpleMap.put("fraction", 5.50d);
        simpleMap.put("sciNote", Double.valueOf("3.7e-4"));
        simpleMap.put("bool", true);
        simpleMap.put("null", JsonNull.NULL);
        simpleMap.put("emptyList", new ArrayList<>());

        simpleList = new ArrayList<>();
        simpleList.add("sample");
        simpleList.add(5l);
        simpleList.add(5.5d);
        simpleList.add(Double.valueOf("9.3e-200"));
        simpleList.add(true);
        simpleList.add(JsonNull.NULL);

        map.put("map", simpleMap);
        map.put("array", simpleList);
        map.put("emptyMap", new HashMap<>());
    }

    @Test
    public void testEncrypt() throws Exception {
        Map<String, Boolean> fields = new HashMap<String, Boolean>();
        fields.put("string", true);
        fields.put("null", false);

        System.out.println(Derulo.toJSON(simpleMap));

        Key key = new SecretKeySpec(new byte[16], "AES");

        JsonEncrypter eCrypter = new JsonEncrypter(key, "AES/CBC/PKCS5Padding");
        eCrypter.setDigest(MessageDigest.getInstance("MD5"));
        eCrypter.setPlainJson(Derulo.toJSON(simpleMap));
        eCrypter.setEncryptedFields(fields);

        System.out.println(eCrypter.getCipherJsonObject().toString());

    }

    @Test
    public void testDecrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        DBP.enableChannel("dev");

        Map<String, Boolean> fields = new HashMap<String, Boolean>();
        fields.put("string", true);
        fields.put("null", false);

        Key key = new SecretKeySpec(new byte[16], "AES");

        JsonEncrypter eCrypter = new JsonEncrypter(key, "AES/CTR/PKCS5Padding");
        eCrypter.setDigest(MessageDigest.getInstance("MD5"));
        String simpleMapJson = Derulo.toJSON(simpleMap);
        eCrypter.setPlainJson(simpleMapJson);
        eCrypter.setEncryptedFields(fields);

        String encrypted = eCrypter.getCipherJson();

        JsonDecrypter dCrypter = new JsonDecrypter(key);
        dCrypter.setCipherJson(encrypted);
        String decrypted = dCrypter.getPlainJson();
        System.out.println(decrypted);
        JsonObject decryptedO = new JsonObject(decrypted);
        assertTrue(decryptedO.equals(simpleMap));
    }
}