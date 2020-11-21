#!/usr/bin/env python3

# Credit: Mateusz Frub
# All instances of keystore are captured by hooking any getInstance() calls.

import frida
import sys

package_name = "INSERT_PACKAGE_HERE"

script = """
var keystoreList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function hookKeystoreConstructor() {
    var keyStoreConstructor = Java.use('java.security.KeyStore').$init.overload("java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String");
    keyStoreConstructor.implementation = function (keyStoreSpi, provider, type) {
        console.log("[ + ] KeyStoreSpi: " + keyStoreSpi + " Provider: " + provider + " Type: " + type);
        return this.$init(keyStoreSpi, provider, type);
    }
}

function hookKeystoreGetInstance() {
    var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String");
    keyStoreGetInstance.implementation = function (type) {
        console.log("[ + ] Keystore Type: " + type);
        var tmp = this.getInstance(type);
        keystoreList.push(tmp);
        return tmp;
    }
}

function hookKeystoreGetInstance_Provider() {
    var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.lang.String");
    keyStoreGetInstance.implementation = function (type, provider) {
        console.log("[ + ] Keystore Type: " + type + " Provider: " + provider);
        var tmp = this.getInstance(type, proivder);
        keystoreList.push(tmp);
        return tmp;
    }
}

function hookKeystoreGetInstance_Provider2() {
    var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.security.Provider");
    keyStoreGetInstance.implementation = function (type, provider) {
        console.log("[ + ] Keystore Type: " + type + " Provider: " + provider);
        var tmp = this.getInstance(type, proivder);
        keystoreList.push(tmp);
        return tmp;
    }
}

function hookKeystoreLoad(dump) {
    var keyStoreLoad = Java.use('java.security.KeyStore')['load'].overload('java.security.KeyStore$LoadStoreParameter');
    keyStoreLoad.implementation = function (param) {
        console.log("[ + ] Keystore Type: " + this.getType() + " Parameter: " + param);
        this.load(param);
        if (dump) console.log("[ + ] Keystore loaded aliases: " + ListAliasesObj(this));
    }
}

function hookKeystoreLoadStream(dump) {
    var keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');
    keyStoreLoadStream.implementation = function (stream, charArray) {
        console.log("[ + ] Keystore Type: " + this.getType() + " Password: " + charArrayToString(charArray) + " InputSteam: " + stream);
        this.load(stream, charArray);
        if (dump) console.log("[ + ] Keystore loaded aliases: " + ListAliasesObj(this));
    }
}

function hookKeystoreStore() {
    var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.security.KeyStore$LoadStoreParameter');
    keyStoreStoreStream.implementation = function (param) {
        console.log("[ + ] Keystore Type: " + this.getType() + " Parameter: " + param);
        this.store(stream, charArray);
    }
}

function hookKeystoreStoreStream() {
    var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.io.OutputStream', '[C');
    keyStoreStoreStream.implementation = function (stream, charArray) {
        console.log("[ + ] Keystore Type: " + this.getType() + " Password: " + charArrayToString(charArray) + " OutputSteam: " + stream);
        this.store(stream, charArray);
    }
}

function hookKeystoreGetKey() {
    var keyStoreGetKey = Java.use('java.security.KeyStore')['getKey'].overload("java.lang.String", "[C");
    keyStoreGetKey.implementation = function (alias, charArray) {
        console.log("[ + ] Alias: " + alias + " Password: " + charArrayToString(charArray));
        return this.getKey(alias, charArray);
    }
}

function hookKeystoreSetEntry() {
    var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setEntry'].overload("java.lang.String", "java.security.KeyStore$Entry", "java.security.KeyStore$ProtectionParameter");
    keyStoreSetKeyEntry.implementation = function (alias, entry, protection) {
        console.log("[ + ] Alias: " + alias + " Entry: " + dumpKeyStoreEntry(entry) + " Protection: " + dumpProtectionParameter(protection));
        return this.setEntry(alias, entry, protection);
    }
}

function hookKeystoreSetKeyEntry() {
    var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;");
    keyStoreSetKeyEntry.implementation = function (alias, key, charArray, certs) {
        console.log("[ + ] Alias: " + alias + " Key: " + key + " Password: " + charArrayToString(charArray) + " Certificates: " + certs);
        return this.setKeyEntry(alias, key, charArray, certs);
    }
}

function hookKeystoreSetKeyEntry2() {
    var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "[B", "[Ljava.security.cert.Certificate;");
    keyStoreSetKeyEntry.implementation = function (alias, key, certs) {
        console.log("[ + ] Alias: " + alias + " Key: " + key + " Certificates: " + certs);
        return this.setKeyEntry(alias, key, certs);
    }
}

function hookKeystoreGetCertificate() {
    var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificate'].overload("java.lang.String");
    keyStoreGetCertificate.implementation = function (alias) {
        console.log("[ + ] Alias: " + alias);
        return this.getCertificate(alias);
    }
}

function hookKeystoreGetCertificateChain() {
    var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificateChain'].overload("java.lang.String");
    keyStoreGetCertificate.implementation = function (alias) {
        console.log("[ + ] Alias: " + alias);
        return this.getCertificateChain(alias);
    }
}

function hookKeystoreGetEntry() {
    var keyStoreGetEntry = Java.use('java.security.KeyStore')['getEntry'].overload("java.lang.String", "java.security.KeyStore$ProtectionParameter");
    keyStoreGetEntry.implementation = function (alias, protection) {
        console.log("[ + ] Alias: " + alias + " Protection: " + dumpProtectionParameter(protection));
        var entry = this.getEntry(alias, protection);
        console.log("[ + ] Entry: " + dumpKeyStoreEntry(entry));
        return entry;
    }
}

function dumpProtectionParameter(protection) {
    if (protection != null) {
        var protectionCls = protection.$className;
        if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
            return "" + protectionCls + " [implement dumping if needed]";
        }
        else if (protectionCls.localeCompare("java.security.KeyStore.CallbackHandlerProtection") == 0) {
            return "" + protectionCls + " [implement dumping if needed]";
        }
        else if (protectionCls.localeCompare("java.security.KeyStore.PasswordProtection") == 0) {
            getPasswordMethod = Java.use('java.security.KeyStore.PasswordProtection')['getPassword'];
            password = getPasswordMethod.call(protection);
            return "password: " + charArrayToString(password);
        }
        else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
            isEncryptionRequiredMethod = Java.use('android.security.KeyStoreParameter')['isEncryptionRequired'];
            result = isEncryptionRequiredMethod.call(protection);
            return "isEncryptionRequired: " + result;
        }
        else
            return "Unknown protection parameter type: " + protectionCls;
    }
    else
        return "null";

}

function dumpKeyStoreEntry(entry) {
    if (entry != null) {
        var entryCls = entry.$className;
        var castedEntry = Java.cast(entry, Java.use(entryCls));
        if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
            var getPrivateKeyEntryMethod = Java.use('java.security.KeyStore$PrivateKeyEntry')['getPrivateKey'];
            var key = getPrivateKeyEntryMethod.call(castedEntry);
            return "" + entryCls + " [implement key dumping if needed] " + key.$className;
        }
        else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
            var getSecretKeyMethod = Java.use('java.security.KeyStore$SecretKeyEntry')['getSecretKey'];
            var key = getSecretKeyMethod.call(castedEntry);
            var keyGetFormatMethod = Java.use(key.$className)['getFormat'];
            var keyGetEncodedMethod = Java.use(key.$className)['getEncoded'];
            if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0)
                return "keyClass: android.security.keystore.AndroidKeyStoreSecretKey can't dump";
            return "keyFormat: " + keyGetFormatMethod.call(key) + ", encodedKey: '" + keyGetEncodedMethod.call(key) + "', key: " + key;
        }
        else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
            return "" + entryCls + " [implement key dumping if needed]";
        }
        else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
            return "" + entryCls + " [implement key dumping if needed]";
        }
        else
            return "Unknown key entry type: " + entryCls;
    }
    else
        return "null";
}

function ListAliasesStatic() {
    var keystoreTypes = ["AndroidKeyStore", "AndroidCAStore", /*"BCPKCS12",*/ "BKS", "BouncyCastle", "PKCS12", /*"PKCS12-DEF"*/];
    keystoreTypes.forEach(function (entry) {
        console.log("[ + ] Keystore Type: " + entry + " \\nAliases: " + ListAliasesType(entry));
    });
    return "[done]";
}

function ListAliasesRuntime() {
    Java.perform(function () {
        console.log("[ + ] Instances: " + keystoreList);
        keystoreList.forEach(function (entry) {
            console.log("[ + ] Keystore object: " + entry + " Type: " + entry.getType() + " \\n" + ListAliasesObj(entry));
        });
    });
    return "[done]";
}

function ListAliasesAndroid() {
    return ListAliasesType("AndroidKeyStore");
}

function ListAliasesType(type) {
    var result = [];
    Java.perform(function () {
        var keyStoreCls = Java.use('java.security.KeyStore');
        var keyStoreObj = keyStoreCls.getInstance(type);
        keyStoreObj.load(null);
        var aliases = keyStoreObj.aliases();
        while (aliases.hasMoreElements()) {
            result.push("'" + aliases.nextElement() + "'");
        }
    });
    return result;
}

function ListAliasesObj(obj) {
    var result = [];
    Java.perform(function () {
        var aliases = obj.aliases();
        while (aliases.hasMoreElements()) {
            result.push(aliases.nextElement() + "");
        }
    });
    return result;
}

function GetKeyStore(keystoreName) {
    var result = null;
    Java.perform(function () {
        for (var i = 0; i < keystoreList.length; i++) {
            if (keystoreName.localeCompare("" + keystoreList[i]) == 0)
                result = keystoreList[i];
        }
    });
    return result;
}

function AliasInfo(keyAlias) {
    var result = {};
    Java.perform(function () {
        var keyStoreCls = Java.use('java.security.KeyStore');
        var keyFactoryCls = Java.use('java.security.KeyFactory');
        var keyInfoCls = Java.use('android.security.keystore.KeyInfo');
        var keySecretKeyFactoryCls = Java.use('javax.crypto.SecretKeyFactory');
        var keyFactoryObj = null;

        var keyStoreObj = keyStoreCls.getInstance('AndroidKeyStore');
        keyStoreObj.load(null);
        var key = keyStoreObj.getKey(keyAlias, null);
        if (key == null) {
            console.log('key does not exist');
            return null;
        }
        try {
            keyFactoryObj = keyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
        } catch (err) {
            keyFactoryObj = keySecretKeyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
        }
        var keyInfo = keyFactoryObj.getKeySpec(key, keyInfoCls.class);
        result.keyAlgorithm = key.getAlgorithm();
        result.keySize = keyInfoCls['getKeySize'].call(keyInfo);
        result.blockModes = keyInfoCls['getBlockModes'].call(keyInfo);
        result.digests = keyInfoCls['getDigests'].call(keyInfo);
        result.encryptionPaddings = keyInfoCls['getEncryptionPaddings'].call(keyInfo);
        result.keyValidityForConsumptionEnd = keyInfoCls['getKeyValidityForConsumptionEnd'].call(keyInfo);
        if (result.keyValidityForConsumptionEnd != null) result.keyValidityForConsumptionEnd = result.keyValidityForConsumptionEnd.toString();
        result.keyValidityForOriginationEnd = keyInfoCls['getKeyValidityForOriginationEnd'].call(keyInfo);
        if (result.keyValidityForOriginationEnd != null) result.keyValidityForOriginationEnd = result.keyValidityForOriginationEnd.toString();
        result.keyValidityStart = keyInfoCls['getKeyValidityStart'].call(keyInfo);
        if (result.keyValidityStart != null) result.keyValidityStart = result.keyValidityStart.toString();
        result.keystoreAlias = keyInfoCls['getKeystoreAlias'].call(keyInfo);
        result.origin = keyInfoCls['getOrigin'].call(keyInfo);
        result.purposes = keyInfoCls['getPurposes'].call(keyInfo);
        result.signaturePaddings = keyInfoCls['getSignaturePaddings'].call(keyInfo);
        result.userAuthenticationValidityDurationSeconds = keyInfoCls['getUserAuthenticationValidityDurationSeconds'].call(keyInfo);
        result.isInsideSecureHardware = keyInfoCls['isInsideSecureHardware'].call(keyInfo);
        result.isInvalidatedByBiometricEnrollment = keyInfoCls['isInvalidatedByBiometricEnrollment'].call(keyInfo);
        try { result.isTrustedUserPresenceRequired = keyInfoCls['isTrustedUserPresenceRequired'].call(keyInfo); } catch (err) { }
        result.isUserAuthenticationRequired = keyInfoCls['isUserAuthenticationRequired'].call(keyInfo);
        result.isUserAuthenticationRequirementEnforcedBySecureHardware = keyInfoCls['isUserAuthenticationRequirementEnforcedBySecureHardware'].call(keyInfo);
        result.isUserAuthenticationValidWhileOnBody = keyInfoCls['isUserAuthenticationValidWhileOnBody'].call(keyInfo);
        try { result.isUserConfirmationRequired = keyInfoCls['isUserConfirmationRequired'].call(keyInfo); } catch (err) { }
    });
    return result;
}

function readStreamToHex(stream) {
    var data = [];
    var byteRead = stream.read();
    while (byteRead != -1) {
        data.push(('0' + (byteRead & 0xFF).toString(16)).slice(-2));
        byteRead = stream.read();
    }
    stream.close();
    return data.join('');
}

function charArrayToString(charArray) {
    if (charArray == null)
        return '(null)';
    else
        return StringCls.$new(charArray);
}

console.log("[ + ] KeyStore hooks loaded!");

Java.perform(function () {
    hookKeystoreGetInstance();
    hookKeystoreGetInstance_Provider();
    hookKeystoreGetInstance_Provider2();
    hookKeystoreConstructor();
    hookKeystoreLoad(false);
    hookKeystoreLoadStream(false);
    hookKeystoreGetKey();
    hookKeystoreSetKeyEntry();
    hookKeystoreGetCertificateChain();
    hookKeystoreGetEntry();
    hookKeystoreSetEntry();
    hookKeystoreSetKeyEntry();
    hookKeystoreSetKeyEntry2();
    hookKeystoreStore();
    hookKeystoreStoreStream()
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
