package infosecadventures.fridademo.fragments;


import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import infosecadventures.fridademo.R;
import infosecadventures.fridademo.utils.EncryptionUtil;

/**
 * A simple {@link Fragment} subclass.
 */
public class EncryptionKey extends Fragment {


    public EncryptionKey() {
        // Required empty public constructor
    }


    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        final View view = inflater.inflate(R.layout.fragment_encryption_key, container, false);
        final EditText plain = view.findViewById(R.id.plain);
        final EditText cipher = view.findViewById(R.id.cipher);
        view.findViewById(R.id.encrypt).setOnClickListener(v -> {
            cipher.setText("");
            String plain_text = plain.getText().toString();
            if (!plain_text.isEmpty()) {
                cipher.setText(EncryptionUtil.encrypt("infosecadventure", plain_text));
            } else {
                Toast.makeText(getContext(), getString(R.string.no_plaintext), Toast.LENGTH_SHORT).show();
            }
        });
        return view;
    }

}
