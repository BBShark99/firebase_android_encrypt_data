package com.example.encryption;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.google.firebase.database.DataSnapshot;
import com.google.firebase.database.DatabaseError;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.ValueEventListener;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class MainActivity extends AppCompatActivity {

    Button btn_send, btn_receive;
    EditText ncon_id, nmincon_id, initialkey_id;
    EditText ini_id, con_id, min_id;
    StringBuffer con_buf, min_buf, ini_buf;


    FirebaseDatabase db;
    DatabaseReference databaseReference;

    String ini_val, con_val, min_val;
    private final static String HEX = "0123456789ABCDEF";
    private final static String ALGORITHM = "AES";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btn_send = findViewById(R.id.btn_send);

        initialkey_id = findViewById(R.id.initialkey_id);
        ncon_id = findViewById(R.id.nconfirmation_id);
        nmincon_id = findViewById(R.id.nminconfirmation_id);

        ini_id = findViewById(R.id.ini_id);
        con_id = findViewById(R.id.ncon_id);
        min_id = findViewById(R.id.nmin_id);

        db = FirebaseDatabase.getInstance();
        databaseReference = db.getReference("chat").child("IDDATA1");

        ini_val = new String();
        con_val = new String();
        min_val = new String();

        btn_send.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                String init_str = initialkey_id.getText().toString().trim().toString();
                String ncon_str = ncon_id.getText().toString().trim().toString();
                String nmincon_str = nmincon_id.getText().toString().trim().toString();

//                ini_fld =Base64.encodeToString(ini_str.getBytes(), Base64.DEFAULT);
//                ncon_fld =Base64.encodeToString(ncon_name.getBytes(), Base64.DEFAULT);
//                nmin_fld =Base64.encodeToString(nmincon_name.getBytes(), Base64.DEFAULT);

                con_buf = encryption("nconfirmations");
                min_buf = encryption("nminconfirmations");

                final HashMap<String, String> result = new HashMap<>();
/// encryption start
                result.put("initialKey", init_str);
                try {
                    result.put(con_buf.toString(), cipher(init_str, ncon_str));
                    result.put(min_buf.toString(), cipher(init_str, nmincon_str));
                } catch (Exception e) {
                    e.printStackTrace();
                }


                databaseReference.setValue(result);
                //// encryrption end
            }
            //
        });

        btn_receive = findViewById(R.id.btn_decrypt);
        btn_receive.setOnClickListener(new View.OnClickListener() { // decryption...
            @Override
            public void onClick(View view) {
                ini_id.setText(ini_val);
                try {
                    // ini_val = initialKey = secret_key && con_val = nconfirmation = data
                    con_id.setText(decipher(ini_val, con_val));

                    min_id.setText(decipher(ini_val, min_val));
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });

        databaseReference.addValueEventListener(new ValueEventListener() {
            @Override
            public void onDataChange(@NonNull DataSnapshot dataSnapshot) {
                int i=0;
                for (DataSnapshot ds1 : dataSnapshot.getChildren()) {
                    String name = ds1.getValue(String.class);
                    if(i == 0) con_val = name;
                    if(i == 1) min_val = name;
                    if(i == 2) ini_val = name;
                    i++;
                }
            }

            @Override
            public void onCancelled(@NonNull DatabaseError databaseError) {

            }
        });
    }

    public StringBuffer encryption(String str){
        try{
            MessageDigest digest = java.security.MessageDigest.getInstance("MD5");
            digest.update(str.getBytes());
            byte messageDigest[] = digest.digest();

            StringBuffer MD5Hash = new StringBuffer();
            for(int i=0; i<messageDigest.length; i++){
                String h = Integer.toHexString(0xFF & messageDigest[i]);
                while(h.length() < 2)
                    h = "0" + h;
                MD5Hash.append(h);
            }
            return MD5Hash;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return new StringBuffer();
    }

    public static String toHex(byte[] stringBytes) {
        StringBuffer result = new StringBuffer(2 * stringBytes.length);
        for (int i = 0; i < stringBytes.length; i++) {
            result.append(HEX.charAt((stringBytes[i] >> 4) & 0x0f)).append(HEX.charAt(stringBytes[i] & 0x0f));
        }

        return result.toString();
    }

    public static String cipher(String secretKey, String data) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), secretKey.getBytes(), 128, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey key = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return toHex(cipher.doFinal(data.getBytes()));
    }

    public static String decipher(String secretKey, String data) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), secretKey.getBytes(), 128, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey key = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.DECRYPT_MODE, key);

        return new String(cipher.doFinal(toByte(data)));
    }

    private static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2), 16).byteValue();
        return result;
    }
}
