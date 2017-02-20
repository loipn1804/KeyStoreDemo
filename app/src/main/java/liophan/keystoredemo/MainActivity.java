package liophan.keystoredemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import butterknife.BindView;
import butterknife.ButterKnife;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String TAG = "LIO";
    private static final String SAMPLE_ALIAS = "MYALIAS";

    @BindView(R.id.edtTextToEncrypt)
    EditText edtTextToEncrypt;
    @BindView(R.id.txtEncrypt)
    TextView txtEncrypt;
    @BindView(R.id.txtDecrypt)
    TextView txtDecrypt;
    @BindView(R.id.btnEncrypt)
    Button btnEncrypt;
    @BindView(R.id.btnDecrypt)
    Button btnDecrypt;

    private EnCryptor encryptor;
    private DeCryptor decryptor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);

        initView();
        initData();
    }

    private void initView() {
        btnEncrypt.setOnClickListener(this);
        btnDecrypt.setOnClickListener(this);
    }

    private void initData() {
        encryptor = new EnCryptor();

        try {
            decryptor = new DeCryptor();
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btnEncrypt:
                encryptText();
                break;
            case R.id.btnDecrypt:
                decryptText();
                break;
        }
    }

    private void decryptText() {
        try {
            txtDecrypt.setText(decryptor.decryptData(SAMPLE_ALIAS, encryptor.getEncryption(), encryptor.getIv()));
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchPaddingException | NoSuchProviderException |
                IOException | InvalidKeyException e) {
            Log.e(TAG, "decryptData() called with: " + e.getMessage(), e);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private void encryptText() {

        try {
            final byte[] encryptedText = encryptor
                    .encryptText(SAMPLE_ALIAS, edtTextToEncrypt.getText().toString());
            txtEncrypt.setText(Base64.encodeToString(encryptedText, Base64.DEFAULT));
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | NoSuchProviderException |
                KeyStoreException | IOException | NoSuchPaddingException | InvalidKeyException e) {
            Log.e(TAG, "onClick() called with: " + e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException | SignatureException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}
