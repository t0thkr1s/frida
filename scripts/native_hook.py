#!/usr/bin/env python3

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

# version 1
script = """
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")
    var NativeHook = Java.use("INSERT_CLASS_HERE");
    NativeHook.INSERT_METHOD_HERE.implementation = function (INSERT_PARAMETER_HERE) {
        console.log("[ * ] The provided parameter is: " + INSERT_PARAMETER_HERE);
        console.log("[ + ] Native method successfully bypassed!");
        return INSERT_RETURN_VALUE_HERE;
  };
});
"""

# version 2
script = """
Interceptor.attach(Module.getExportByName('INSERT_LIBRARY_HERE', 'INSERT_METHOD_HERE'), {
    onLeave: function(retval) {
        console.log("[ * ] Changing return value...");
        console.log("[ * ] The original return value is: " + retval);
        retval.replace(INSERT_RETURN_VALUE_HERE);
        console.log("[ + ] The changed return value is: " + retval);
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
