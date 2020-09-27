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
import android.view.Window
import android.widget.TextView

import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

import com.huawei.hms.support.api.fido.bioauthn.BioAuthnCallback
import com.huawei.hms.support.api.fido.bioauthn.BioAuthnManager
import com.huawei.hms.support.api.fido.bioauthn.BioAuthnPrompt
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
class MainActivity : AppCompatActivity() {

    // In the scenario where BioAuthnPrompt.PromptInfo.Builder.setDeviceCredentialAllowed(true) is used in EMUI 9.x or
    // earlier, fingerprint authentication may work once only. You can solve this problem in one of the following ways:
    // 1. The activity has only one singleton BioAuthnPrompt object. Do not create the object repeatedly.
    // 2. After the authentication is complete, call the recreate() method of the activity.
    // 3. Close the activity and open it again.
    private var bioAuthnPrompt: BioAuthnPrompt? = null

    private var resultTextView: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportRequestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.activity_main)
        resultTextView = findViewById(R.id.resultTextView)
        bioAuthnPrompt = createBioAuthnPrompt()
    }

    private fun createBioAuthnPrompt(): BioAuthnPrompt {
        // call back
        val callback = object : BioAuthnCallback() {
            override fun onAuthError(errMsgId: Int, errString: CharSequence) {
                showResult("Authentication error. errorCode=$errMsgId,errorMessage=$errString")
            }

            override fun onAuthSucceeded(result: BioAuthnResult) {
                if (result.cryptoObject != null) {
                    showResult("Authentication succeeded. CryptoObject=" + result.cryptoObject!!)
                } else {
                    showResult("Authentication succeeded. CryptoObject=null")
                }
            }

            override fun onAuthFailed() {
                showResult("Authentication failed.")
            }
        }
        return BioAuthnPrompt(this, ContextCompat.getMainExecutor(this), callback)
    }

    /**
     * Shows the fingerprint prompt without CryptoObject and allows the user to use the device PIN and password for
     * authentication.
     *
     * @param view View
     */
    fun btnFingerAuthenticateWithoutCryptoObjectClicked(view: View) {
        // Checks whether fingerprint authentication is available.
        val bioAuthnManager = BioAuthnManager(this)
        val errorCode = bioAuthnManager.canAuth()
        if (errorCode != 0) {
            resultTextView!!.text = ""
            showResult("Can not authenticate. errorCode=$errorCode")
            return
        }

        // build prompt info
        val builder = BioAuthnPrompt.PromptInfo.Builder().setTitle("This is the title.")
                .setSubtitle("This is the subtitle")
                .setDescription("This is the description")

        // The user will first be prompted to authenticate with biometrics, but also given the option to
        // authenticate with their device PIN, pattern, or password. setNegativeButtonText(CharSequence) should
        // not be set if this is set to true.
        builder.setDeviceCredentialAllowed(true)

        // Set the text for the negative button. setDeviceCredentialAllowed(true) should not be set if this button text
        // is set.
        // builder.setNegativeButtonText("This is the 'Cancel' button.");

        val info = builder.build()
        resultTextView!!.text = "Start fingerprint authentication without CryptoObject.\nAuthenticating......\n"
        bioAuthnPrompt!!.auth(info)
    }

    /**
     * Shows the fingerprint prompt with CryptoObject.
     *
     * @param view View
     */
    fun btnFingerAuthenticateWithCryptoObjectClicked(view: View) {
        // Checks whether fingerprint authentication is available.
        val bioAuthnManager = BioAuthnManager(this)
        val errorCode = bioAuthnManager.canAuth()

        if (errorCode != 0) {
            resultTextView!!.text = ""
            showResult("Can not authenticate. errorCode=$errorCode")
            return
        }

        // build prompt info
        val builder = BioAuthnPrompt.PromptInfo.Builder().setTitle("This is the title.")
                .setSubtitle("This is the subtitle.")
                .setDescription("This is the description.")

        // The user will first be prompted to authenticate with biometrics, but also given the option to
        // authenticate with their device PIN, pattern, or password. setNegativeButtonText(CharSequence) should
        // not be set if this is set to true.
        // builder.setDeviceCredentialAllowed(true);

        // Set the text for the negative button. setDeviceCredentialAllowed(true) should not be set if this
        // button text is set.
        builder.setNegativeButtonText("This is the 'Cancel' button.")

        val info = builder.build()

        // Construct CryptoObject.
        val cipher = HwBioAuthnCipherFactory("hw_test_fingerprint", true).cipher
        if (cipher == null) {
            showResult("Failed to create Cipher object.")
            return
        }
        val crypto = CryptoObject(cipher)

        resultTextView!!.text = "Start fingerprint authentication with CryptoObject.\nAuthenticating......\n"

        // When user CryptoObject, BiometricPrompt.PromptInfo.Builder.setDeviceCredentialAllowed(true) is not allow.
        // Call BiometricPrompt.authenticate(BiometricPrompt.PromptInfo info) if
        // BiometricPrompt.PromptInfo.Builder.setDeviceCredentialAllowed(true) is set to true.
        bioAuthnPrompt!!.auth(info, crypto)
    }

    /**
     * Sends a 3D facial authentication request to the user device.
     *
     * @param view View
     */
    fun btnFaceAuthenticateWithoutCryptoObjectClicked(view: View) {
        // check camera permission
        val permissionCheck = ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.CAMERA)
        if (permissionCheck != PackageManager.PERMISSION_GRANTED) {
            showResult("The camera permission is not enabled. Please enable it.")

            // request camera permissions
            ActivityCompat.requestPermissions(this@MainActivity, arrayOf(Manifest.permission.CAMERA), 1)
            return
        }

        // call back
        val callback = object : BioAuthnCallback() {
            override fun onAuthError(errMsgId: Int, errString: CharSequence) {
                showResult("Authentication error. errorCode=" + errMsgId + ",errorMessage=" + errString
                        + if (errMsgId == 1012) " The camera permission may not be enabled." else "")
            }

            override fun onAuthHelp(helpMsgId: Int, helpString: CharSequence) {
                resultTextView!!
                        .append("Authentication help. helpMsgId=$helpMsgId,helpString=$helpString\n")
            }

            override fun onAuthSucceeded(result: BioAuthnResult) {
                showResult("Authentication succeeded.")
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
        val builder = AlertDialog.Builder(this@MainActivity)
        builder.setTitle("Authentication Result")
        builder.setMessage(msg)
        builder.setPositiveButton("OK", null)
        builder.show()
        resultTextView!!.append(msg + "\n")
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
 * @param storeKey story key name
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

    @RequiresApi(api = Build.VERSION_CODES.M)
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

    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun createSecretKey(storeKeyName: String, isInvalidatedByBiometricEnrollment: Boolean) {
        try {
            keyStore!!.load(null)
            val keyParamBuilder = KeyGenParameterSpec.Builder(storeKeyName,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // This key is authorized to be used only if the user has been authenticated.
                    .setUserAuthenticationRequired(isUserAuthenticationRequired)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                keyParamBuilder.setInvalidatedByBiometricEnrollment(isInvalidatedByBiometricEnrollment)
            }
            keyGenerator!!.init(keyParamBuilder.build())
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