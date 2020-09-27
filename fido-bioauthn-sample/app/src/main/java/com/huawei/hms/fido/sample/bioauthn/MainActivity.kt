/*
 * Copyright 2020. Huawei Technologies Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package com.huawei.hms.fido.sample.bioauthn

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.TextView

import com.huawei.hms.support.api.fido.bioauthn.BioAuthnCallback
import com.huawei.hms.support.api.fido.bioauthn.FingerprintManager
import com.huawei.hms.support.api.fido.bioauthn.BioAuthnResult
import com.huawei.hms.support.api.fido.bioauthn.CryptoObject
import com.huawei.hms.support.api.fido.bioauthn.FaceManager

import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.util.concurrent.Executors

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

/**
 * Huawei HMS Core FIDO BioAuthn Sample
 *
 * @author Huawei HMS
 * @since 2019-11-19
 */
class MainActivity : Activity() {

    private var fingerprintManager: FingerprintManager? = null

    private var resultTextView: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        resultTextView = findViewById(R.id.resultTextView)
        fingerprintManager = createFingerprintManager()
    }

    private fun createFingerprintManager(): FingerprintManager {
        // call back
        val callback = object : BioAuthnCallback() {
            override fun onAuthError(errMsgId: Int, errString: CharSequence?) {
                showResult("Authentication error. errorCode=$errMsgId,errorMessage=$errString")
            }

            override fun onAuthSucceeded(result: BioAuthnResult) {
                showResult("Authentication succeeded. CryptoObject=" + result.cryptoObject)
            }

            override fun onAuthFailed() {
                showResult("Authentication failed.")
            }
        }
        return FingerprintManager(this, Executors.newSingleThreadExecutor(), callback)
    }

    /**
     * Do the fingerprint authentication without CryptoObject
     *
     * @param view View
     */
    fun btnFingerAuthenticateWithoutCryptoObjectClicked(view: View) {
        // Checks whether fingerprint authentication is available.
        val errorCode = fingerprintManager!!.canAuth()
        if (errorCode != 0) {
            resultTextView!!.text = ""
            showResult("Can not authenticate. errorCode=$errorCode")
            return
        }

        resultTextView!!.text = "Start fingerprint authentication without CryptoObject.\nAuthenticating......\n"
        fingerprintManager!!.auth()
    }

    /**
     * Do the fingerprint authentication with CryptoObject.
     *
     * @param view View
     */
    fun btnFingerAuthenticateWithCryptoObjectClicked(view: View) {
        // Checks whether fingerprint authentication is available.
        val errorCode = fingerprintManager!!.canAuth()

        if (errorCode != 0) {
            resultTextView!!.text = ""
            showResult("Can not authenticate. errorCode=$errorCode")
            return
        }

        // Construct CryptoObject.
        val cipher = HwBioAuthnCipherFactory("hw_test_fingerprint", true).cipher
        if (cipher == null) {
            showResult("Failed to create Cipher object.")
            return
        }
        val crypto = CryptoObject(cipher)

        resultTextView!!.text = "Start fingerprint authentication with CryptoObject.\nAuthenticating......\n"

        fingerprintManager!!.auth(crypto)
    }

    /**
     * Sends a 3D facial authentication request to the user device.
     *
     * @param view View
     */
    fun btnFaceAuthenticateWithoutCryptoObjectClicked(view: View) {
        // check camera permission
        var permissionCheck = 0
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            permissionCheck = this.checkSelfPermission(Manifest.permission.CAMERA)
        }
        if (permissionCheck != PackageManager.PERMISSION_GRANTED) {
            showResult("The camera permission is not enabled. Please enable it.")

            // request camera permissions
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                this.requestPermissions(arrayOf(Manifest.permission.CAMERA), 1)
            }
            return
        }

        // call back
        val callback = object : BioAuthnCallback() {
            override fun onAuthError(errMsgId: Int, errString: CharSequence?) {
                showResult("Authentication error. errorCode=" + errMsgId + ",errorMessage=" + errString
                        + if (errMsgId == 1012) " The camera permission may not be enabled." else "")
            }

            override fun onAuthHelp(helpMsgId: Int, helpString: CharSequence?) {
                resultTextView!!
                        .append("Authentication help. helpMsgId=$helpMsgId,helpString=$helpString\n")
            }

            override fun onAuthSucceeded(result: BioAuthnResult) {
                showResult("Authentication succeeded. CryptoObject=" + result.cryptoObject)
            }

            override fun onAuthFailed() {
                showResult("Authentication failed.")
            }
        }

        // Cancellation Signal
        val cancellationSignal = CancellationSignal()

        val faceManager = FaceManager(this)

        // Checks whether 3D facial authentication can be used.
        val errorCode = faceManager.canAuth()
        if (errorCode != 0) {
            resultTextView!!.text = ""
            showResult("Can not authenticate. errorCode=$errorCode")
            return
        }

        // flags
        val flags = 0

        // Authentication messsage handler.
        val handler: Handler? = null

        // Recommended CryptoObject to be set to null. KeyStore is not associated with face authentication in current
        // version. KeyGenParameterSpec.Builder.setUserAuthenticationRequired() must be set false in this scenario.
        val crypto: CryptoObject? = null

        resultTextView!!.text = "Start face authentication.\nAuthenticating......\n"
        faceManager.auth(crypto, cancellationSignal, flags, callback, handler)
    }

    private fun showResult(msg: String) {
        runOnUiThread {
            val builder = AlertDialog.Builder(this@MainActivity)
            builder.setTitle("Authentication Result")
            builder.setMessage(msg)
            builder.setPositiveButton("OK", null)
            builder.show()
            resultTextView!!.append(msg + "\n")
        }
    }
}

/**
 * Cipher Factory
 *
 * @author Huawei HMS
 * @since 2019-11-19
 */
internal class HwBioAuthnCipherFactory
/**
 * constructed function
 *
 * @param storeKey                     story key name
 * @param isUserAuthenticationRequired Sets whether the key is authorized to be used only if the user has been
 * authenticated.
 */
(private val storeKey: String, private val isUserAuthenticationRequired: Boolean) {

    private var keyStore: KeyStore? = null

    private var keyGenerator: KeyGenerator? = null

    var cipher: Cipher? = null
        private set

    init {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                initDefaultCipherObject()
            } catch (e: Exception) {
                cipher = null
                Log.e(TAG, "Failed to init Cipher. " + e.message)
            }

        } else {
            cipher = null
            Log.e(TAG, "Failed to init Cipher.")
        }
    }

    private fun initDefaultCipherObject() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to get an instance of KeyStore(AndroidKeyStore). " + e.message, e)
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get an instance of KeyGenerator(AndroidKeyStore)." + e.message,
                    e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get an instance of KeyGenerator(AndroidKeyStore)." + e.message, e)
        }

        createSecretKey(storeKey, true)

        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC
                    + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get an instance of Cipher", e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException("Failed to get an instance of Cipher", e)
        }

        initCipher(cipher!!, storeKey)
    }

    private fun initCipher(cipher: Cipher, storeKeyName: String) {
        try {
            keyStore!!.load(null)
            val secretKey = keyStore!!.getKey(storeKeyName, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher. " + e.message, e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher. " + e.message, e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher. " + e.message, e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher. " + e.message, e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher. " + e.message, e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher. " + e.message, e)
        }

    }

    private fun createSecretKey(storeKeyName: String, isInvalidatedByBiometricEnrollment: Boolean) {
        try {
            keyStore!!.load(null)
            var keyParamBuilder: KeyGenParameterSpec.Builder? = null
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyParamBuilder = KeyGenParameterSpec.Builder(storeKeyName,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        // This key is authorized to be used only if the user has been authenticated.
                        .setUserAuthenticationRequired(isUserAuthenticationRequired)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                keyParamBuilder!!.setInvalidatedByBiometricEnrollment(isInvalidatedByBiometricEnrollment)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator!!.init(keyParamBuilder!!.build())
            }
            keyGenerator!!.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to create secret key. " + e.message, e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException("Failed to create secret key. " + e.message, e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to create secret key. " + e.message, e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to create secret key. " + e.message, e)
        }

    }

    companion object {
        private val TAG = "HwBioAuthnCipherFactory"
    }
}