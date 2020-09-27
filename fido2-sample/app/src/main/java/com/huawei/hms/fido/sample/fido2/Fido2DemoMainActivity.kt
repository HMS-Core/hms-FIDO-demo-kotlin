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

package com.huawei.hms.fido.sample.fido2

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.TextUtils
import android.util.Log
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView

import androidx.appcompat.app.AppCompatActivity

import com.huawei.hms.fido.sample.fido2.server.FidoServerSimulator
import com.huawei.hms.fido.sample.fido2.server.IFidoServer
import com.huawei.hms.fido.sample.fido2.server.ServerUtils
import com.huawei.hms.fido.sample.fido2.server.param.ServerAuthenticatorSelectionCriteria
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialCreationOptionsRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegDeleteRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfo
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfoRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerStatus
import com.huawei.hms.support.api.fido.fido2.Attachment
import com.huawei.hms.support.api.fido.fido2.Fido2
import com.huawei.hms.support.api.fido.fido2.Fido2AuthenticationRequest
import com.huawei.hms.support.api.fido.fido2.Fido2AuthenticationResponse
import com.huawei.hms.support.api.fido.fido2.Fido2Client
import com.huawei.hms.support.api.fido.fido2.Fido2Intent
import com.huawei.hms.support.api.fido.fido2.Fido2IntentCallback
import com.huawei.hms.support.api.fido.fido2.Fido2RegistrationRequest
import com.huawei.hms.support.api.fido.fido2.Fido2RegistrationResponse
import com.huawei.hms.support.api.fido.fido2.Fido2Response
import com.huawei.hms.support.api.fido.fido2.NativeFido2AuthenticationOptions
import com.huawei.hms.support.api.fido.fido2.NativeFido2RegistrationOptions
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialCreationOptions
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialRequestOptions
import java.util.Locale

/**
 * Fido2 Demo MainActivity
 * For details about operations related to the app server and FIDO server, please refer to related standards.
 * https://www.w3.org/TR/webauthn/#webauthn-client
 *
 * @author Huawei HMS
 * @since 2020-03-08
 */
class Fido2DemoMainActivity : AppCompatActivity() {

    private var userVerificationLevelAdapter: ArrayAdapter<*>? = null

    private var authAttachModeAdapter: ArrayAdapter<*>? = null

    private var attestConveyancePreferenceAdapter: ArrayAdapter<*>? = null

    private var residentKeyTypeAdapter: ArrayAdapter<*>? = null

    private var regInfoView: TextView? = null

    private var userVerificationSp: Spinner? = null

    private var attachmentSp: Spinner? = null

    private var attestationSp: Spinner? = null

    private var residentKeySp: Spinner? = null

    private var fido2Client: Fido2Client? = null

    private val authnServerPublicKeyCredentialCreationOptionsRequest: ServerPublicKeyCredentialCreationOptionsRequest?
        get() {
            val request = ServerPublicKeyCredentialCreationOptionsRequest()
            val userName = userName
            request.username = userName
            request.displayName = userName

            return request
        }

    private val regServerPublicKeyCredentialCreationOptionsRequest: ServerPublicKeyCredentialCreationOptionsRequest?
        get() {
            val request = ServerPublicKeyCredentialCreationOptionsRequest()

            val userName = userName
            request.username = userName
            request.displayName = userName

            val userVeriLevel = getSpinnerSelect(userVerificationSp!!.selectedItem)
            val attachmentMode = getSpinnerSelect(attachmentSp!!.selectedItem)

            var residentKey: Boolean? = null
            if (residentKeySp!!.selectedItem != null) {
                val residentKeyString = getSpinnerSelect(residentKeySp!!.selectedItem)
                if (TextUtils.isEmpty(residentKeyString)) {
                    residentKey = null
                } else if ("false" == residentKeyString) {
                    residentKey = false
                } else if ("true" == residentKeyString) {
                    residentKey = true
                }
            }
            val attestConveyancePreference = getSpinnerSelect(attestationSp!!.selectedItem)

            val selection = getAuthenticatorSelectionCriteria(userVeriLevel, attachmentMode, residentKey)
            request.authenticatorSelection = selection

            request.attestation = attestConveyancePreference
            return request
        }

    private val userName: String
        get() = "FidoTestUser"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fido2_demo_main)
        initView()
        fido2Client = Fido2.getFido2Client(this)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != Activity.RESULT_OK) {
            showError(getString(R.string.unknow_err))
            return
        }
        when (requestCode) {
            // Receive the registration response.
            Fido2Client.REGISTRATION_REQUEST -> {
                val fido2RegistrationResponse = fido2Client!!.getFido2RegistrationResponse(data)
                reg2Server(fido2RegistrationResponse)
            }

            // Receive the authentication response.
            Fido2Client.AUTHENTICATION_REQUEST -> {
                val fido2AuthenticationResponse = fido2Client!!.getFido2AuthenticationResponse(data)
                auth2Server(fido2AuthenticationResponse)
            }
            else -> {
            }
        }
    }

    fun onClickRegistration(view: View) {
        if (!fido2Client!!.isSupported) {
            showMsg("FIDO2 is not supported.")
            return
        }

        val fidoServer = initFidoServer()

        val request = regServerPublicKeyCredentialCreationOptionsRequest ?: return
        // Obtain the challenge value and related policy from the FIDO server, and initiate a Fido2RegistrationRequest
        // request.
        val response = fidoServer.getAttestationOptions(request)
        if (ServerStatus.OK != response.status) {
            Log.e(TAG, getString(R.string.reg_fail) + response.errorMessage)
            showError(getString(R.string.reg_fail) + response.errorMessage)
        }
        val fido2ClientTmp = fido2Client;
        if (fido2ClientTmp != null) {
            val publicKeyCredentialCreationOptions = ServerUtils.convert2PublicKeyCredentialCreationOptions(fido2ClientTmp, response)
            reg2Fido2Client(publicKeyCredentialCreationOptions)
        }
    }

    private fun reg2Fido2Client(publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions) {
        val registrationOptions = NativeFido2RegistrationOptions.DEFAULT_OPTIONS
        val registrationRequest = Fido2RegistrationRequest(publicKeyCredentialCreationOptions, null)

        // Call Fido2Client.getRegistrationIntent to obtain a Fido2Intent instance and start the FIDO client
        // registration process.
        fido2Client!!.getRegistrationIntent(registrationRequest, registrationOptions, object : Fido2IntentCallback {
            override fun onSuccess(fido2Intent: Fido2Intent) {
                // Start the FIDO client registration process through Fido2Client.REGISTRATION_REQUEST.
                fido2Intent.launchFido2Activity(this@Fido2DemoMainActivity, Fido2Client.REGISTRATION_REQUEST)
            }

            override fun onFailure(errorCode: Int, errString: CharSequence) {
                showError(getString(R.string.reg_fail) + errorCode + "=" + errString)
            }
        })
    }

    fun onClickAuthentication(view: View) {
        if (!fido2Client!!.isSupported) {
            showMsg("FIDO2 is not supported.")
            return
        }

        val fidoServer = initFidoServer()
        val request = authnServerPublicKeyCredentialCreationOptionsRequest ?: return

        // Obtain the challenge value and related policy from the FIDO server, and initiate a Fido2AuthenticationRequest
        // request.
        val response = fidoServer.getAssertionOptions(request)
        if (ServerStatus.OK != response.status) {
            Log.e(TAG, getString(R.string.authn_fail) + response.errorMessage)
            showError(getString(R.string.authn_fail) + response.errorMessage)
            return
        }

        val attachmentMode = getSpinnerSelect(attachmentSp!!.selectedItem)
        val isUseSelectedPlatformAuthenticator = Attachment.PLATFORM.value == attachmentMode
        val fido2ClientTmp = fido2Client;
        if (fido2ClientTmp != null) {
            val publicKeyCredentialCreationOptions = ServerUtils.convert2PublicKeyCredentialRequestOptions(fido2ClientTmp, response, isUseSelectedPlatformAuthenticator)
            authn2Fido2Client(publicKeyCredentialCreationOptions)
        }
    }

    private fun authn2Fido2Client(publicKeyCredentialCreationOptions: PublicKeyCredentialRequestOptions) {
        val authenticationOptions = NativeFido2AuthenticationOptions.DEFAULT_OPTIONS
        val authenticationRequest = Fido2AuthenticationRequest(publicKeyCredentialCreationOptions, null)

        // Call Fido2Client.getAuthenticationIntent to obtain a Fido2Intent instance and start the FIDO client
        // authentication process.
        fido2Client!!.getAuthenticationIntent(authenticationRequest, authenticationOptions, object : Fido2IntentCallback {
            override fun onSuccess(fido2Intent: Fido2Intent) {
                // Start the FIDO client authentication process through Fido2Client.AUTHENTICATION_REQUEST.
                fido2Intent.launchFido2Activity(this@Fido2DemoMainActivity, Fido2Client.AUTHENTICATION_REQUEST)
            }

            override fun onFailure(errorCode: Int, errString: CharSequence) {
                showError(getString(R.string.authn_fail) + errorCode + "=" + errString)
            }
        })
    }

    fun onClickGetRegInfo(view: View) {
        val fidoServer = initFidoServer()
        getRegInfo(fidoServer, true)
    }

    fun onClickDeregistration(view: View) {
        val fidoServer = initFidoServer()
        val userName = userName
        val request = ServerRegDeleteRequest()
        request.username = userName

        val response = fidoServer.delete(request)
        if (ServerStatus.OK != response.status) {
            Log.e(TAG, getString(R.string.delete_register_info_fail) + response.errorMessage)
            showError(getString(R.string.delete_register_info_fail) + response.errorMessage)
            return
        }
        regInfoView!!.text = ""
        showMsg(getString(R.string.delete_register_info_success))
    }

    private fun reg2Server(fido2RegistrationResponse: Fido2RegistrationResponse) {
        if (!fido2RegistrationResponse.isSuccess) {
            showError(getString(R.string.reg_fail), fido2RegistrationResponse)
            return
        }
        val fidoServer = initFidoServer()

        val request = ServerUtils
                .convert2ServerAttestationResultRequest(fido2RegistrationResponse.authenticatorAttestationResponse)

        val response = fidoServer.getAttestationResult(request)
        if (ServerStatus.OK != response.status) {
            Log.e(TAG, getString(R.string.reg_fail) + response.errorMessage)
            showError(getString(R.string.reg_fail) + response.errorMessage)
            return
        }
        getRegInfo(fidoServer, false)
        showMsg(getString(R.string.reg_success))
    }

    private fun auth2Server(fido2AuthenticationResponse: Fido2AuthenticationResponse) {
        if (!fido2AuthenticationResponse.isSuccess) {
            showError(getString(R.string.authn_fail), fido2AuthenticationResponse)
            return
        }

        val fidoServer = initFidoServer()

        val request = ServerUtils
                .convert2ServerAssertionResultRequest(fido2AuthenticationResponse.authenticatorAssertionResponse)

        val response = fidoServer.getAssertionResult(request)
        if (ServerStatus.OK != response.status) {
            Log.e(TAG, getString(R.string.authn_fail) + response.errorMessage)
            showError(getString(R.string.authn_fail) + response.errorMessage)
            return
        }
        showMsg(getString(R.string.authn_success))
    }

    private fun showMsg(message: String) {
        runOnUiThread {
            val builder = AlertDialog.Builder(this@Fido2DemoMainActivity)
            builder.setTitle(getString(R.string.message_title))
            builder.setMessage(message)
            builder.setPositiveButton(getString(R.string.confirm_btn), null)
            builder.show()
        }
    }

    private fun getRegInfo(fidoServer: IFidoServer, showMsgDlg: Boolean) {
        val request = ServerRegInfoRequest()
        val username = userName
        request.username = username

        val response = fidoServer.getRegInfo(request)
        if (ServerStatus.OK != response.status) {
            Log.e(TAG, getString(R.string.get_register_info_fail) + response.errorMessage)
            if (showMsgDlg) {
                showError(getString(R.string.get_register_info_fail))
            }
            return
        }
        showRegInfo(response.infos)
        if (showMsgDlg) {
            showMsg(getString(R.string.get_register_info_success))
        }
    }

    private fun showRegInfo(regInfos: List<ServerRegInfo>?) {
        val infoStrb = StringBuilder()
        infoStrb.append(getString(R.string.cp_reg_info)).append(System.lineSeparator())
        if (regInfos != null) {
            var index = 0
            for (regInfo in regInfos) {
                infoStrb.append(++index)
                        .append(". ")
                        .append(getString(R.string.credential_id))
                        .append(regInfo.credentialId)
                        .append(System.lineSeparator())
            }
        }
        regInfoView!!.text = infoStrb
    }

    private fun showError(message: String, fido2Response: Fido2Response) {
        val errMsgBuilder = StringBuilder()
        errMsgBuilder.append(message)
                .append("Fido2Status: ")
                .append(fido2Response.fido2Status)
                .append("=")
                .append(fido2Response.fido2StatusMessage)
                .append(String.format(Locale.ENGLISH, "(CtapStatus: 0x%x=%s)", fido2Response.ctapStatus,
                        fido2Response.ctapStatusMessage))

        runOnUiThread {
            val builder = AlertDialog.Builder(this@Fido2DemoMainActivity)
            builder.setTitle(getString(R.string.error_title))
            builder.setMessage(errMsgBuilder)
            builder.setPositiveButton(getString(R.string.confirm_btn), null)
            builder.show()
        }
    }

    private fun showError(message: String) {
        runOnUiThread {
            val builder = AlertDialog.Builder(this@Fido2DemoMainActivity)
            builder.setTitle(getString(R.string.error_title))
            builder.setMessage(message)
            builder.setPositiveButton(getString(R.string.confirm_btn), null)
            builder.show()
        }
    }

    private fun getAuthenticatorSelectionCriteria(
            userVerificationLevel: String?, attachmentMdoe: String?, residentKey: Boolean?): ServerAuthenticatorSelectionCriteria {
        val selectionCriteria = ServerAuthenticatorSelectionCriteria()

        if (!TextUtils.isEmpty(userVerificationLevel)) {
            selectionCriteria.userVerification = userVerificationLevel
        } else {
            selectionCriteria.userVerification = null
        }

        if (!TextUtils.isEmpty(attachmentMdoe)) {
            selectionCriteria.authenticatorAttachment = attachmentMdoe
        } else {
            selectionCriteria.authenticatorAttachment = null
        }

        selectionCriteria.isRequireResidentKey = residentKey
        return selectionCriteria
    }

    private fun initFidoServer(): IFidoServer {
        return FidoServerSimulator()
    }

    private fun initView() {
        regInfoView = findViewById(R.id.txt_show_log_area)
        userVerificationSp = findViewById(R.id.sp_user_required_level)
        attachmentSp = findViewById(R.id.sp_auth_attach_mode)
        attestationSp = findViewById(R.id.sp_attest_conveyance_preference)
        residentKeySp = findViewById(R.id.sp_residentkey_type)
        supportActionBar!!.hide()
        userVerificationLevelAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, android.R.id.text1, USER_REQUIRED_LEVEL_LIST)
        userVerificationSp!!.adapter = userVerificationLevelAdapter

        authAttachModeAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, android.R.id.text1, AUTH_ATTACH_MODE)
        attachmentSp!!.adapter = authAttachModeAdapter

        attestConveyancePreferenceAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1,
                android.R.id.text1, ATTEST_CONVEYANCE_PREFERENCE)
        attestationSp!!.adapter = attestConveyancePreferenceAdapter

        residentKeyTypeAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, android.R.id.text1, RESIDENT_KEY_TYPE)
        residentKeySp!!.adapter = residentKeyTypeAdapter
    }

    companion object {
        private val TAG = "Fido2DemoMainActivity"

        private val USER_REQUIRED_LEVEL_LIST = arrayOf("null", "required", "preferred", "discouraged")

        private val AUTH_ATTACH_MODE = arrayOf("null", "platform", "cross-platform")

        private val ATTEST_CONVEYANCE_PREFERENCE = arrayOf("null", "none", "indirect", "direct")

        private val RESIDENT_KEY_TYPE = arrayOf("null", "true", "false")

        private fun getSpinnerSelect(select: Any?): String? {
            val data = select as String?
            return if (select == null || TextUtils.isEmpty(data) || "null" == data) {
                null
            } else data
        }
    }
}