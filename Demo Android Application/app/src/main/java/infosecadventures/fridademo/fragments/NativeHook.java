package infosecadventures.fridademo.fragments;


import android.app.AlertDialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import infosecadventures.fridademo.R;

public class NativeHook extends Fragment {

    static {
        System.loadLibrary("native_hook");
    }

    public NativeHook() {
        // Required empty public constructor
    }

    native boolean checkPassword(String password);

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_native_hooks, container, false);
        final EditText password = view.findViewById(R.id.password);
        view.findViewById(R.id.password_check).setOnClickListener(v -> {
            if (password.getText().toString().isEmpty()) {
                Toast.makeText(getContext(), "Password is not provided!", Toast.LENGTH_SHORT).show();
                return;
            }
            if (checkPassword(password.getText().toString())) {
                new AlertDialog.Builder(getActivity())
                        .setTitle(getString(R.string.granted))
                        .setMessage(getString(R.string.success_pass))
                        .setPositiveButton("Dismiss", (dialog, which) -> dialog.dismiss())
                        .show();
            } else {
                new AlertDialog.Builder(getActivity())
                        .setTitle(getString(R.string.denied))
                        .setMessage(getString(R.string.fail_pass))
                        .setPositiveButton("Dismiss", (dialog, which) -> dialog.dismiss())
                        .show();
            }
        });
        return view;
    }
}
