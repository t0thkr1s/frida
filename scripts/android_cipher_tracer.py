#!/usr/bin/env python3

# Credit: Mateusz Frub
# Hooks will attempt to trace calls to Cipher class and hexdump buffer passed/returned during encryption/decryption.
# All instances of Cipher class are captured by hooking any getInstance() call.

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function hookCipherGetInstance1() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload("java.lang.String");
    cipherGetInstance.implementation = function (type) {
        console.log("[ + ] Cipher type: " + type);
        var tmp = this.getInstance(type);
        console.log("[ + ] Cipher object: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherGetInstance2() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.security.Provider');
    cipherGetInstance.implementation = function (transformation, provider) {
        console.log("[ + ] Transformation: " + transformation + "  Provider: " + provider);
        var tmp = this.getInstance(transformation, provider);
        console.log("[ + ] Cipher object: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherGetInstance3() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.lang.String');
    cipherGetInstance.implementation = function (transformation, provider) {
        console.log("[ + ] Transformation: " + transformation + "  Provider: " + provider);
        var tmp = this.getInstance(transformation, provider);
        console.log("[ + ] Cipher object: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherInit1() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate');
    cipherInit.implementation = function (mode, cert) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Certificate: " + cert + " Cipher object: " + this);
        var tmp = this.init(mode, cert);
    }
}

function hookCipherInit2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key');
    cipherInit.implementation = function (mode, secretKey) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Secret Key: " + secretKey.$className + " Cipher object: " + this);
        var tmp = this.init(mode, secretKey);
    }
}

function hookCipherInit3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters');
    cipherInit.implementation = function (mode, secretKey, alParam) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Secret Key: " + secretKey.$className + " Parameter:" + alParam + " Cipher object: " + this);
        var tmp = this.init(mode, secretKey, alParam);
    }
}

function hookCipherInit4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
    cipherInit.implementation = function (mode, secretKey, spec) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Secret Key: " + secretKey.$className + " Specification:" + spec + " Cipher object: " + this);
        var tmp = this.init(mode, secretKey, spec);
    }
}

function hookCipherInit5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, cert, secureRandom) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Certificate: " + cert + " Secure Random: " + secureRandom + " Cipher object: " + this);
        var tmp = this.init(mode, cert, secureRandom);
    }
}

function hookCipherInit6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, secureRandom) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Secret Key: " + secretKey.$className + " Secure Random: " + secureRandom + " Cipher object: " + this);
        var tmp = this.init(mode, secretKey, secureRandom);
    }
}

function hookCipherInit7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, spec, secureRandom) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Secret Key: " + secretKey.$className + " Specification: " + spec + " Secure Random: " + secureRandom + " Cipher object: " + this);
        var tmp = this.init(mode, secretKey, spec, secureRandom);
    }
}

function hookCipherInit8() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, alParam, secureRandom) {
        console.log("[ + ] Cipher mode: " + decodeMode(mode) + " Secret Key: " + secretKey.$className + " Parameter: " + alParam + " Secure Random: " + secureRandom + " Cipher object: " + this);
        var tmp = this.init(mode, secretKey, alParam, secureRandom);
    }
}

function hookDoFinal1() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload();
    cipherInit.implementation = function () {
        console.log("[ + ] Cipher object: " + this);
        var tmp = this.doFinal();
        dumpByteArray('[ + ] Result', tmp);
        return tmp;
    }
}

function hookDoFinal2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B');
    cipherInit.implementation = function (byteArr) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.doFinal(byteArr);
        dumpByteArray('[ + ] Out buffer', tmp);
        return tmp;
    }
}

function hookDoFinal3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int');
    cipherInit.implementation = function (byteArr, a1) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] Out buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1);
        dumpByteArray('[ + ] Out buffer', byteArr);
        return tmp;
    }
}

function hookDoFinal4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    cipherInit.implementation = function (a1, a2) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', a1.array());
        var tmp = this.doFinal(a1, a2);
        dumpByteArray('[ + ] Out buffer', a2.array());
        return tmp;
    }
}

function hookDoFinal5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int');
    cipherInit.implementation = function (byteArr, a1, a2) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2);
        dumpByteArray('[ + ] Out buffer', tmp);
        return tmp;
    }
}

function hookDoFinal6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr);
        dumpByteArray('[ + ] Out buffer', outputArr);
        return tmp;
    }
}

function hookDoFinal7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
        dumpByteArray('[ + ] Out buffer', outputArr);
        return tmp;
    }
}

function hookUpdate1() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B');
    cipherInit.implementation = function (byteArr) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ]In buffer', byteArr);
        var tmp = this.update(byteArr);
        dumpByteArray('[ + ] Out buffer', tmp);
        return tmp;
    }
}

function hookUpdate2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    cipherInit.implementation = function (byteArr, outputArr) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr.array());
        var tmp = this.update(byteArr, outputArr);
        dumpByteArray('[ + ] Out buffer', outputArr.array());
        return tmp;
    }
}

function hookUpdate3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int');
    cipherInit.implementation = function (byteArr, a1, a2) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.update(byteArr, a1, a2);
        dumpByteArray('[ + ] Out buffer', tmp);
        return tmp;
    }
}

function hookUpdate4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr);
        dumpByteArray('[ + ] Out buffer', outputArr);
        return tmp;
    }
}

function hookUpdate5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        console.log("[ + ] Cipher object: " + this);
        dumpByteArray('[ + ] In buffer', byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr, a4);
        dumpByteArray('[ + ] Out buffer', outputArr);
        return tmp;
    }
}

function ListCiphers() {
    Java.perform(function () {
        for (var i = 0; i < cipherList.length; i++) {
            console.log("[" + i + "] " + cipherList[i]);
        }
    });
    return "[done]";
}

function GetCipher(cipherName) {
    var result = null;
    Java.perform(function () {
        for (var i = 0; i < cipherList.length; i++) {
            if (cipherName.localeCompare("" + cipherList[i]) == 0)
                result = cipherList[i];
        }
    });
    return result;
}

function doUpdate(cipherName, bytes) {
    Java.perform(function () {
        var cipher = GetCipher(cipherName);
        cipher.update(bytes);
    });
}

function doFinal(cipherName) {
    Java.perform(function () {
        var cipher = GetCipher(cipherName);
        cipher.final(bytes);
    });
}

function decodeMode(mode) {
    if (mode == 1)
        return "Encrypt";
    else if (mode == 2)
        return "Decrypt";
    else if (mode == 3)
        return "Wrap";
    else if (mode == 4)
        return "Unwrap";
}

function dumpByteArray(title, byteArr) {
    if (byteArr != null) {
        try {
            var buff = new ArrayBuffer(byteArr.length)
            var dtv = new DataView(buff)
            for (var i = 0; i < byteArr.length; i++) {
                dtv.setUint8(i, byteArr[i]);
            }
            console.log(title + ":");
            console.log(hexdumpJS(dtv.buffer, 0, byteArr.length))
        } catch (error) {
            console.log("[ - ] Exception has occured in hexdump...") 
        }
    }
    else {
        console.log("[ - ] Byte array is null!");
    }
}

function fillUp(value, count, fillWith) {
    var l = count - value.length;
    var ret = "";
    while (--l > -1)
        ret += fillWith;
    return ret + value;
}

function hexdumpJS(arrayBuffer, offset, length) {

    var view = new DataView(arrayBuffer);
    offset = offset || 0;
    length = length || arrayBuffer.byteLength;

    var out = fillUp("Offset", 8, " ") + "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\\n";
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
}

console.log("[ + ] Cipher hooks loaded!");

Java.perform(function () {
    hookCipherGetInstance1();
    hookCipherGetInstance2();
    hookCipherGetInstance3();
    hookCipherInit1();
    hookCipherInit2();
    hookCipherInit3();
    hookCipherInit4();
    hookCipherInit5();
    hookCipherInit6();
    hookCipherInit7();
    hookCipherInit8();
    hookDoFinal1();
    hookDoFinal2();
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal6();
    hookDoFinal7();
    hookUpdate1();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();
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
