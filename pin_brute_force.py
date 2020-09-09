#!/usr/bin/env python3

import frida
import sys

package_name = "infosecadventures.fridademo"

# for non-static classes
script = """
Java.perform(function() {
    console.log("[ * ] Starting PIN Brute-force, please wait...");
    Java.choose("infosecadventures.fridademo.utils.PinUtil", {
        onMatch: function(instance) {
            console.log("[ * ] Instance found in memory: " + instance);
            for (var i = 1000; i < 9999; i++) {
                if (instance.checkPin(i + "") == true) {
                    console.log("[ + ] Found correct PIN: " + i);
                }
            }
        },
        onComplete: function() {}
    });
});

"""

# for static classes
script = """
Java.perform(function() {
    console.log("[ * ] Starting PIN Brute-force, please wait...")
    var PinUtil = Java.use("infosecadventures.fridademo.utils.PinUtil");

    for (var i = 1000; i < 9999; i++) {
        if (PinUtil.checkPin(i + "") == true) {
            console.log("[ + ] Found correct PIN: " + i);
        }
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
