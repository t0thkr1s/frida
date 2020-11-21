#!/usr/bin/env python3

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
 Java.perform(function() {
    var FLAG_SECURE = 0x2000;

    var Runnable = Java.use("java.lang.Runnable");
    var DisableSecureRunnable = Java.registerClass({
       name: "INSERT_PACKAGE_HERE.DisableSecureRunnable",
       implements: [Runnable],
       fields: {
          activity: "android.app.Activity",
       },
       methods: {
          $init: [{
             returnType: "void",
             argumentTypes: ["android.app.Activity"],
             implementation: function (activity) {
                this.activity.value = activity;
             }
          }],
          run: function() {
             var flags = this.activity.value.getWindow().getAttributes().flags.value;
             flags &= ~FLAG_SECURE;
             this.activity.value.getWindow().setFlags(flags, FLAG_SECURE);
             console.log("[ + ] SECURE flag is now disabled!");
          }
       }
    });

   Java.choose("INSERT_MAINACTIVITY_HERE", {
      "onMatch": function (instance) {
         var runnable = DisableSecureRunnable.$new(instance);
         instance.runOnUiThread(runnable);
      },
      "onComplete": function () {}
   });
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
