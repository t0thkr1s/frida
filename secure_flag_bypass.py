#!/usr/bin/env python3

import frida
import sys

script = """
 Java.perform(function() {
    var FLAG_SECURE = 0x2000;

    var Runnable = Java.use("java.lang.Runnable");
    var DisableSecureRunnable = Java.registerClass({
       name: "infosecadventures.fridademo.DisableSecureRunnable",
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
             console.log("[ * ] SECURE flag is now disabled!");
          }
       }
    });

   Java.choose("infosecadventures.fridademo.MainActivity", {
      "onMatch": function (instance) {
         var runnable = DisableSecureRunnable.$new(instance);
         instance.runOnUiThread(runnable);
      },
      "onComplete": function () {}
   });
});
"""

process = frida.get_usb_device().attach('infosecadventures.fridademo')
exploit = process.create_script(script)
print('[ * ] Running Frida Demo application')
exploit.load()
sys.stdin.read()
