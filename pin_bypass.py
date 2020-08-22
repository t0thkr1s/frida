#!/usr/bin/env python3

import frida

script = """
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")
    var MainActivity = Java.use("infosecadventures.fridademo.utils.PinUtil");
    MainActivity.checkPin.implementation = function(pin) {
        console.log("[ + ] PIN check successfully bypassed!")
        return true;
    }
});
"""

process = frida.get_usb_device().attach('infosecadventures.fridademo')
exploit = process.create_script(script)
print('[ * ] Running Frida Demo application')
exploit.load()
sys.stdin.read()
