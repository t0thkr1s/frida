#!/usr/bin/env python3

import frida
import sys

package_name = "infosecadventures.fridademo"

# version 1
script = """
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")
    var NativeHook = Java.use("infosecadventures.fridademo.fragments.NativeHook");
    NativeHook.checkPassword.implementation = function (password) {
        console.log("[ * ] The provided password is: " + password);
        console.log("[ + ] Native method successfully bypassed!");
        return true;
  };
});
"""

# version 2
script = """
Interceptor.attach(Module.getExportByName('libnative_hook.so', 'Java_infosecadventures_fridademo_fragments_NativeHook_checkPassword'), {
    onLeave: function(retval) {
        console.log("[ * ] Changing return value...");
        console.log("[ * ] The original return value is: " + retval);
        retval.replace(1);
        console.log("[ + ] The changed return value is: " + retval);
    }
});
"""

try:
    print("[ * ] Looking for app: " + package_name)
    device = frida.get_usb_device()
    print("[ * ] Launching app...")
    pid = device.spawn([package_name])
    device.resume(pid)
    session = device.attach(pid)
    exploit = session.create_script(script)
    print("[ + ] App launched. Loading exploit...")
    exploit.load()
    sys.stdin.read()
except frida.ServerNotRunningError:
    print("[ - ] Frida server is not running! Exiting...")
except frida.NotSupportedError:
    print("[ - ] Unable to find application. Please, install it first!")
except frida.ProcessNotFoundError:
    print("[ - ] Unable to find process. Launch the app and try again!")
except KeyboardInterrupt:
    print("\n[ - ] Interrupted. Exiting...")
