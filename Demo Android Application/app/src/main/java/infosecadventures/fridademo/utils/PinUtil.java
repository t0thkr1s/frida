package infosecadventures.fridademo.utils;

import android.util.Base64;

public class PinUtil {

    public static boolean checkPin(String pin) {
        return pin.equals(new String(Base64.decode("NDg2Mw==", Base64.DEFAULT)));
    }
}
