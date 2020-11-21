#!/usr/bin/env python3

# Credit: Mateusz Frub
# PBEKeySpec tracer allows to see parameters (including password) from which PBKDF keys are generated.

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function hookSecretKeyFactory_getInstance() {
    var func = Java.use('javax.crypto.SecretKeyFactory')['getInstance'];
    func.implementation = function(flag) {
        console.log("[ + ] Flag: " + flag );
        return this.getInstance(flag);
    }   
}

function hookPBEKeySpec1() {
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C');
    PBEKeySpec.implementation = function(pass) {
        console.log("[ + ] PBEKeySpec password: " + charArrayToString(pass));
        return this.$init(pass);
    }   
}

function hookPBEKeySpec2() {
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int');
    PBEKeySpec.implementation = function(pass, salt, iter) {
        console.log("[ + ] PBEKeySpec password: " + charArrayToString(pass)  +  " Iteration: " + iter);
        dumpByteArray("[ + ] Salt", salt)
        return this.$init(pass, salt, iter);
    }   
}

function hookPBEKeySpec3() {
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int', 'int');
    PBEKeySpec.implementation = function(pass, salt, iter, keyLength) {
        console.log("[ + ] PBEKeySpec password: " + charArrayToString(pass)  +  " Iteration: " + iter + " Key Length: " + keyLength);
        dumpByteArray("[ + ] Salt", salt)
        return this.$init(pass, salt, iter, keyLength);
    }   
}

function charArrayToString(charArray) {
    if(charArray == null)
        return '(null)';
    else
        return StringCls.$new(charArray); 
}

function dumpByteArray(title, byteArr) {
    if(byteArr!=null)
    {
        try{ 
            var buff = new ArrayBuffer(byteArr.length)
            var dtv = new DataView(buff)
            for(var i = 0; i < byteArr.length; i++){
                dtv.setUint8(i,byteArr[i]);
            }
            console.log(title + ":");
            console.log(hexdumpJS(dtv.buffer,0,byteArr.length))
        } catch(error){
            console.log("[ - ] Exception has occured in hexdump...")
        }
    }
    else
    {
        console.log("[ - ] Byte array is null!");
    }
}

function fillUp (value, count, fillWith) {
    var l = count - value.length;
    var ret = "";
    while (--l > -1)
        ret += fillWith;
    return ret + value;
}

function hexdumpJS (arrayBuffer, offset, length) {

    var view = new DataView(arrayBuffer);
    offset = offset || 0;
    length = length || arrayBuffer.byteLength;

    var out = fillUp("[ + ] Offset: ", 8, " ") + "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\\n";
    var row = "";
    for (var i = 0; i < length; i += 16) {
        row += fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
        var n = Math.min(16, length - offset);
        var string = "";
        for (var j = 0; j < 16; ++j) {
            if (j < n) {
                var value = view.getUint8(offset);
                string += (value >= 32 && value < 128) ? String.fromCharCode(value) : ".";
                row += fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
                offset++;
            }
            else {
                row += "   ";
                string += " "; 
            }
        }
        row += " " + string + "\\n";
    }
    out += row;
    return out;
};

console.log("[ + ] SecretKeyFactory hooks loaded!");
Java.perform(function () {
    hookPBEKeySpec1();
    hookPBEKeySpec2();
    hookPBEKeySpec3();    
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
