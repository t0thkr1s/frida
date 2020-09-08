#!/usr/bin/env python3

import frida
import sys

# For non-static classes
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

# For static classes
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

process = frida.get_usb_device().attach('infosecadventures.fridademo')
exploit = process.create_script(script)
print('[ * ] Running Frida Demo application')
exploit.load()
sys.stdin.read()
