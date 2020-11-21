#!/usr/bin/env python3

# Credit: Mateusz Frub
# Hooks KeyGenParameterSpec.Builder and gives visibility into how keystore keys are protected.

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function hookSetInvalidatedByBiometricEnrollment() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setInvalidatedByBiometricEnrollment'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setInvalidatedByBiometricEnrollment(): " + flag);
        return this.setInvalidatedByBiometricEnrollment(flag);
    }   
}

function hookSetUnlockedDeviceRequired() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUnlockedDeviceRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setUnlockedDeviceRequired(): " + flag);
        return this.setUnlockedDeviceRequired(flag);
    }   
}

function hookSetUserConfirmationRequired() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserConfirmationRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setUserConfirmationRequired(): " + flag);
        return this.setUserConfirmationRequired(flag);
    }   
}

function hookSetUserAuthenticationValidityDurationSeconds() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserAuthenticationValidityDurationSeconds'];
    keyGenParameterSpec.implementation = function(sec) {
        console.log("[ + ] Hooked setUserAuthenticationValidityDurationSeconds(): " + sec);
        return this.setUserAuthenticationValidityDurationSeconds(sec);
    }   
}

function hookSetUserAuthenticationRequired() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserAuthenticationRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setUserAuthenticationRequired(): " + flag);
        return this.setUserAuthenticationRequired(flag);
    }   
}

function hookSetUserPresenceRequired() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserPresenceRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setUserPresenceRequired(): " + flag);
        return this.setUserPresenceRequired(flag);
    }   
}

function hookSetRandomizedEncryptionRequired() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setRandomizedEncryptionRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setRandomizedEncryptionRequired(): " + flag);
        return this.setRandomizedEncryptionRequired(flag);
    }   
}


function hookSetInvalidatedByBiometricEnrollment() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setInvalidatedByBiometricEnrollment'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setInvalidatedByBiometricEnrollment(): " + flag);
        return this.setInvalidatedByBiometricEnrollment(flag);
    }   
}

function hookSetIsStrongBoxBacked() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setIsStrongBoxBacked'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setIsStrongBoxBacked(): " + flag);
        return this.setIsStrongBoxBacked(flag);
    }   
}

function hookSetUserAuthenticationValidityDurationSeconds() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserAuthenticationValidityDurationSeconds'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setUserAuthenticationValidityDurationSeconds(): " + flag);
        return this.setUserAuthenticationValidityDurationSeconds(flag);
    }   
}

function hookSetKeySize() {
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setKeySize'];
    keyGenParameterSpec.implementation = function(flag) {
        console.log("[ + ] Hooked setKeySize(): " + flag);
        return this.setKeySize(flag);
    }   
}

console.log("[ + ] KeyGenParameterSpec.Builder hooks loaded!");

Java.perform(function () {
    hookSetInvalidatedByBiometricEnrollment();
    try {
        hookSetUnlockedDeviceRequired();
    } catch (error) {
        console.log("[ - ] hookSetUnlockedDeviceRequired not supported on this android version.")
    }
    try {
        hookSetUserConfirmationRequired();
    } catch (error) {
        console.log("[ - ] hookSetUserConfirmationRequired not supported on this android version.")
    }
    try {
        hookSetUserAuthenticationValidityDurationSeconds();
    } catch (error) {
        console.log("[ - ] hookSetUserAuthenticationValidityDurationSeconds not supported on this android version.")
    }
    hookSetUserAuthenticationRequired();
    try {
        hookSetUserPresenceRequired();
    } catch (error) {
        console.log("[ - ] hookSetUserPresenceRequired not supported on this android version.")
    }
    hookSetRandomizedEncryptionRequired();
    hookSetInvalidatedByBiometricEnrollment()
    try {
        hookSetIsStrongBoxBacked();
    } catch (error) {
        console.log("[ - ] hookSetIsStrongBoxBacked not supported on this android version.")
    }
    hookSetUserAuthenticationValidityDurationSeconds()
    hookSetKeySize();
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
