package infosecadventures.fridademo.fragments;


import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import infosecadventures.fridademo.R;
import infosecadventures.fridademo.utils.PinUtil;

/**
 * A simple {@link Fragment} subclass.
 */
public class PinBypass extends Fragment {


    public PinBypass() {
        // Required empty public constructor
    }


    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_pin_bypass, container, false);
        final EditText pin = view.findViewById(R.id.pin);
        view.findViewById(R.id.pin_check).setOnClickListener(v -> {
            if (pin.getText().toString().isEmpty()) {
                Toast.makeText(getContext(), "PIN is not provided!", Toast.LENGTH_SHORT).show();
                return;
            }
            if (PinUtil.checkPin(pin.getText().toString())) {
                new AlertDialog.Builder(getActivity())
                        .setTitle(getString(R.string.granted))
                        .setMessage(getString(R.string.success_pin))
                        .setPositiveButton("Dismiss", (dialog, which) -> dialog.dismiss())
                        .show();
            } else {
                new AlertDialog.Builder(getActivity())
                        .setTitle(getString(R.string.denied))
                        .setMessage(getString(R.string.fail_pin))
                        .setPositiveButton("Dismiss", (dialog, which) -> dialog.dismiss())
                        .show();
            }
        });
        return view;
    }
}
