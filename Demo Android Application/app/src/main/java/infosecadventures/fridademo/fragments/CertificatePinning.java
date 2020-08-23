package infosecadventures.fridademo.fragments;


import android.app.AlertDialog;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import java.io.IOException;
import java.util.Objects;

import infosecadventures.fridademo.R;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * A simple {@link Fragment} subclass.
 */
public class CertificatePinning extends Fragment {


    public CertificatePinning() {
        // Required empty public constructor
    }

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        final View view = inflater.inflate(R.layout.fragment_certificate_pinning, container, false);
        view.findViewById(R.id.pinned_ssl_connection).setOnClickListener(v -> {

            CertificatePinner certificatePinner = new CertificatePinner.Builder()
                    .add("httpbin.org",
                            "sha256/flUN9mYPmbQZ0jCTHMo2iEhYuYQrJ3iKdeRV7x+8s50=")
                    .add("example.com",
                            "sha256/JSMzqOOrtyOT1kmau6zKhgT676hGgczD5VMdRMyJZFA=")
                    .build();

            OkHttpClient okHttpClient = new OkHttpClient.Builder()
                    .certificatePinner(certificatePinner)
                    .build();

            Request request = new Request.Builder()
                    .url("https://httpbin.org/json")
                    .build();

            okHttpClient.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Objects.requireNonNull(getActivity()).runOnUiThread(() -> new AlertDialog.Builder(getActivity())
                            .setTitle(R.string.certificate_unknown)
                            .setMessage(R.string.failed_tls_connection)
                            .setPositiveButton("Dismiss", (dialog, which) -> dialog.dismiss())
                            .show());
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    Log.d("DEBUG", Objects.requireNonNull(response.body()).string());
                    Objects.requireNonNull(getActivity()).runOnUiThread(() -> {
                        if (response.isSuccessful()) {
                            new AlertDialog.Builder(getActivity())
                                    .setTitle(R.string.connection_success)
                                    .setMessage(R.string.check_proxy)
                                    .setPositiveButton("Dismiss", (dialog, which) -> dialog.dismiss())
                                    .show();
                        }
                    });

                }
            });

        });
        return view;
    }
}
