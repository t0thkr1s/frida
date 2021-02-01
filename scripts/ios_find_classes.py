#!/usr/bin/env python3

import frida
import sys

bundle = "INSERT_BUNDLE_HERE"

script = """
var search_class = ['INSERT_CLASS_HERE'];

if (ObjC.available)
{
	for (var className in ObjC.classes) {
		if (Array.isArray(search_class) && search_class.length) {
			for (var i = 0; i < search_class.length; i++) {
				if (className.toLowerCase().includes(search_class[i].toLowerCase())) {
					console.log(className)
				}
			}
		}
		else {
			console.log(className);
		}
	}
}
else {
    console.log('[ - ] Objective-C Runtime is not available!');
}
"""

try:
    print("[ * ] Looking for app: " + bundle)
    device = frida.get_usb_device(10)
    print("[ * ] Launching app...")
    pid = device.spawn([bundle])
    device.resume(pid)
    session = device.attach(pid)
    exploit = session.create_script(script)
    print("[ + ] App launched. Dumping Classes...")
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
