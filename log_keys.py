#!/usr/bin/env python3

import frida

script = """
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")
    var EncryptionUtil = Java.use("infosecadventures.fridademo.utils.EncryptionUtil");
    EncryptionUtil.encrypt.implementation = function(key, value) {
        console.log("Key: ");
        console.log(key);
        console.log("Value: ");
        console.log(value);
        return this.encrypt(key, value);
    }
});
"""

process = frida.get_usb_device().attach('infosecadventures.fridademo')
exploit = process.create_script(script)
print('[ * ] Running Frida Demo application')
exploit.load()
sys.stdin.read()
