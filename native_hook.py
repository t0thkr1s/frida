#!/usr/bin/env python3

import frida
import sys

# version 1
script = """
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")
    var NativeHook = Java.use("infosecadventures.fridademo.fragments.NativeHook");
    NativeHook.checkPassword.implementation = function (password) {
        console.log("[ * ] The provided password is: " + password);
        console.log("[ * ] Native method successfully bypassed!");
        return true;
  };
});
"""

# version 2
# script = """
# Interceptor.attach(Module.getExportByName('libnative_hook.so', 'Java_infosecadventures_fridademo_fragments_NativeHook_checkPassword'), {
#     onLeave: function(retval) {
#         console.log("[ * ] Changing return value...");
#         console.log("[ * ] The original return value is: " + retval);
#         retval.replace(1);
#         console.log("[ * ] The changed return value is: " + retval);
#     }
# });
# """

process = frida.get_usb_device().attach('infosecadventures.fridademo')
exploit = process.create_script(script)
print('[ * ] Running Frida Demo application')
exploit.load()
sys.stdin.read()
