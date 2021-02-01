#!/usr/bin/env python3

import frida
import sys

bundle = "INSERT_BUNDLE_HERE"

script = """
var cookieJar = {};
var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
for (var i = 0, l = cookies.count(); i < l; i++) {
    var cookie = cookies['- objectAtIndex:'](i);
    cookieJar[cookie.Name()] = cookie.Value().toString();
}
console.log(JSON.stringify(cookieJar, null, 2));
"""

try:
    print("[ * ] Looking for app: " + bundle)
    device = frida.get_usb_device(10)
    print("[ * ] Launching app...")
    pid = device.spawn([bundle])
    device.resume(pid)
    session = device.attach(pid)
    exploit = session.create_script(script)
    print("[ + ] App launched. Printing Cookies...")
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
