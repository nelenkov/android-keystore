package org.nick.androidkeystore;

import java.math.BigInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.nick.androidkeystore.android.security.KeyStore;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

public class KeystoreActivity extends Activity implements OnClickListener {

    private static final String TAG = KeystoreActivity.class.getSimpleName();

    private static final String EXTRA_CIPHERTEXT = "org.nick.androidkeystore.CIPHERTEXT";
    private static final String EXTRA_KEY_NAME = "org.nick.androidkeystore.KEY_NAME";
    private static final String EXTRA_PLAINTEXT = "org.nick.androidkeystore.PLAINTEXT";

    public static final String OLD_UNLOCK_ACTION = "android.credentials.UNLOCK";

    public static final String UNLOCK_ACTION = "com.android.credentials.UNLOCK";
    public static final String RESET_ACTION = "com.android.credentials.RESET";

    private static final String KEY_NAME = "test_key";
    private static final String PLAIN_TEXT = "Hello, KeyStore!";

    private static int keyNum = 0;

    private TextView encryptedText;
    private TextView decryptedText;

    private Button encryptButton;
    private Button decryptButton;
    private Button listButton;
    private Button resetButton;

    private ListView keyList;

    private KeyStore ks;

    private String encryptionKeyName;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        super.onCreate(savedInstanceState);

        setContentView(R.layout.main);

        findViews();

        if (savedInstanceState != null) {
            encryptedText.setText(savedInstanceState
                    .getString(EXTRA_CIPHERTEXT));
            encryptionKeyName = savedInstanceState.getString(EXTRA_KEY_NAME);

            String plaintext = savedInstanceState.getString(EXTRA_PLAINTEXT);
            decryptedText.setText(plaintext);
        }

        ks = KeyStore.getInstance();

        displayKeystoreState();
    }

    abstract class KeystoreTask extends AsyncTask<Void, Void, String[]> {

        Exception error;

        @Override
        protected void onPreExecute() {
            setProgressBarIndeterminateVisibility(true);
            toggleControls(false);
        }

        @Override
        protected String[] doInBackground(Void... params) {
            try {
                return doWork();
            } catch (Exception e) {
                error = e;
                Log.e(TAG, "Error: " + e.getMessage(), e);

                return null;
            }
        }

        protected abstract String[] doWork();

        @Override
        protected void onPostExecute(String[] result) {
            setProgressBarIndeterminateVisibility(false);
            toggleControls(true);

            if (error != null) {
                Toast.makeText(KeystoreActivity.this,
                        "Error: " + error.getMessage(), Toast.LENGTH_LONG)
                        .show();

                return;
            }


            updateUi(result);
        }

        protected abstract void updateUi(String[] result);
    }

    private void toggleControls(boolean enable) {
        encryptButton.setEnabled(enable);
        decryptButton.setEnabled(enable);
        listButton.setEnabled(enable);
        resetButton.setEnabled(enable);
    }

    private void displayKeystoreState() {
        new KeystoreTask() {

            @Override
            protected String[] doWork() {
                Log.d(TAG, "Keystore state: " + ks.state());
                String status = String.format("Keystore state:%s", ks.state()
                        .toString());

                return new String[] { status };
            }

            @Override
            protected void updateUi(String[] result) {
                setTitle(result[0]);
            }
        }.execute();
    }

    private void findViews() {
        encryptedText = (TextView) findViewById(R.id.encrypted_text);
        decryptedText = (TextView) findViewById(R.id.decrypted_text);

        encryptButton = (Button) findViewById(R.id.encrypt_button);
        encryptButton.setOnClickListener(this);

        decryptButton = (Button) findViewById(R.id.decrypt_button);
        decryptButton.setOnClickListener(this);

        listButton = (Button) findViewById(R.id.list_button);
        listButton.setOnClickListener(this);

        resetButton = (Button) findViewById(R.id.reset_button);
        resetButton.setOnClickListener(this);

        keyList = (ListView) findViewById(R.id.key_list);
    }

    @Override
    protected void onResume() {
        super.onResume();

        displayKeystoreState();

        if (ks.state() == KeyStore.State.UNLOCKED) {
            showKeys();
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);

        String ciphertext = encryptedText.getText().toString();
        String plaintext = decryptedText.getText().toString();
        if (ciphertext != null) {
            outState.putString(EXTRA_CIPHERTEXT, encryptedText.getText()
                    .toString());
            outState.putString(EXTRA_KEY_NAME, encryptionKeyName);
        }
        if (plaintext != null) {
            outState.putString(EXTRA_PLAINTEXT, plaintext);
        }

    }

    @Override
    public void onClick(View v) {
        if (ks.state() != KeyStore.State.UNLOCKED) {
            Toast.makeText(
                    this,
                    "Keystore is locked or not initialized. Retry operation "
                            + "after unlock activity returns.",
                    Toast.LENGTH_LONG).show();
            unlock();

            // unlocking is in a separate activity, stop here
            return;
        }

        try {
            if (v.getId() == R.id.reset_button) {
                reset();
                //                resetKeystore();
            } else if (v.getId() == R.id.list_button) {
                showKeys();
                //                testKeystore();
            } else if (v.getId() == R.id.encrypt_button) {
                encrypt();
            } else if (v.getId() == R.id.decrypt_button) {
                if (encryptedText.getText() == null
                        || encryptedText.getText().equals("")) {
                    Toast.makeText(this, "No encrypted text found.",
                            Toast.LENGTH_SHORT).show();

                    return;
                }

                decrypt();
            }
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error: " + e.getMessage(), e);
            Toast.makeText(this, "Unexpected error: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        }
    }

    private void decrypt() {
        final String ciphertext = encryptedText.getText().toString();
        new KeystoreTask() {

            @Override
            protected String[] doWork() {
                byte[] keyBytes = ks.get(encryptionKeyName);
                if (keyBytes == null) {
                    Log.w(TAG, "Encryption key not found in keystore: "
                            + encryptionKeyName);

                    return null;
                }

                SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
                String plaintext = Crypto.decrypt(ciphertext, key);

                return new String[] { plaintext };
            }

            @Override
            protected void updateUi(String[] result) {
                if (result == null) {
                    Toast.makeText(KeystoreActivity.this,
                            "Encryption key not found in keystore.",
                            Toast.LENGTH_SHORT).show();

                    return;
                }

                decryptedText.setText(result[0]);
            }
        }.execute();
    }

    private void encrypt() {
        new KeystoreTask() {

            @Override
            protected String[] doWork() {
                SecretKey key = Crypto.generateKey();
                encryptionKeyName = KEY_NAME + keyNum;
                boolean success = ks.put(encryptionKeyName, key.getEncoded());
                Log.d(TAG, "put key success: " + success);
                checkRc(success);

                keyNum++;
                String ciphertext = Crypto.encrypt(PLAIN_TEXT, key);

                return new String[] { ciphertext };
            }

            @Override
            protected void updateUi(String[] result) {
                encryptedText.setText(result[0]);

                showKeys();

            }
        }.execute();
    }

    private void reset() {
        new KeystoreTask() {

            @Override
            protected String[] doWork() {
                String[] keys = ks.saw("");
                for (String key : keys) {
                    boolean success = ks.delete(key);
                    Log.d(TAG, "delete key success: " + success);
                    checkRc(success);
                }

                return null;
            }

            @Override
            protected void updateUi(String[] result) {
                encryptedText.setText("");
                decryptedText.setText("");

                showKeys();
            }
        }.execute();
    }

    private void showKeys() {
        new KeystoreTask() {

            @Override
            protected String[] doWork() {
                String[] keyNames = ks.saw("");

                return keyNames;
            }

            @Override
            protected void updateUi(String[] keyNames) {
                ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                        KeystoreActivity.this,
                        android.R.layout.simple_list_item_1, keyNames);
                keyList.setAdapter(adapter);

                Log.d(TAG, "Keys: ");
                for (String keyName : keyNames) {
                    byte[] keyBytes = ks.get(keyName);

                    Log.d(TAG, String.format("\t%s: %s", keyName,
                            new BigInteger(keyBytes).toString()));
                }
            }
        }.execute();
    }

    private void unlock() {
        if (ks.state() == KeyStore.State.UNLOCKED) {
            return;
        }

        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
                startActivity(new Intent(OLD_UNLOCK_ACTION));
            } else {
                startActivity(new Intent(UNLOCK_ACTION));
            }
        } catch (ActivityNotFoundException e) {
            Log.e(TAG, "No UNLOCK activity: " + e.getMessage(), e);
            Toast.makeText(this, "No keystore unlock activity found.",
                    Toast.LENGTH_SHORT).show();

            return;
        }
    }

    @SuppressWarnings("unused")
    private void resetKeystore() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            Toast.makeText(this, "Reset not supported on pre-ICS devices",
                    Toast.LENGTH_SHORT).show();
        } else {
            startActivity(new Intent(RESET_ACTION));
        }
    }

    @SuppressWarnings("unused")
    private void testKeystore() {
        boolean success = ks.lock();
        if (!success) {
            Log.d(TAG, "lock() last error = " + rcToStr(ks.getLastError()));
        }
        success = ks.unlock("foo");
        if (!success) {
            Log.d(TAG, "unlock() last error = " + rcToStr(ks.getLastError()));
        }
        success = ks.password("foobar");
        if (!success) {
            Log.d(TAG, "password() last error = " + rcToStr(ks.getLastError()));
        }
        success = ks.reset();
        if (!success) {
            Log.d(TAG, "reset() last error = " + rcToStr(ks.getLastError()));
        }
        success = ks.isEmpty();
        if (!success) {
            Log.d(TAG, "isEmpty() last error = " + rcToStr(ks.getLastError()));
        }
    }

    private void checkRc(boolean success) {
        if (!success) {
            String errorStr = rcToStr(ks.getLastError());
            Log.d(TAG, "last error = " + errorStr);

            throw new RuntimeException("Keystore error: " + errorStr);
        }
    }

    private static final String rcToStr(int rc) {
        switch (rc) {
        case KeyStore.NO_ERROR:
            return "NO_ERROR";
        case KeyStore.LOCKED:
            return "LOCKED";
        case KeyStore.UNINITIALIZED:
            return "UNINITIALIZED";
        case KeyStore.SYSTEM_ERROR:
            return "SYSTEM_ERROR";
        case KeyStore.PROTOCOL_ERROR:
            return "PROTOCOL_ERROR";
        case KeyStore.PERMISSION_DENIED:
            return "PERMISSION_DENIED";
        case KeyStore.KEY_NOT_FOUND:
            return "KEY_NOT_FOUND";
        case KeyStore.VALUE_CORRUPTED:
            return "VALUE_CORRUPTED";
        case KeyStore.UNDEFINED_ACTION:
            return "UNDEFINED_ACTION";
        case KeyStore.WRONG_PASSWORD:
            return "WRONG_PASSWORD";
        default:
            return "Unknown RC";
        }
    }
}
