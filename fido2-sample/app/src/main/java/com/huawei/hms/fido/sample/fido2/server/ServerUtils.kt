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

package com.huawei.hms.fido.sample.fido2.server

import android.util.Log

import com.huawei.hms.fido.sample.fido2.server.param.ServerAssertionResultRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerAssertionResultResponseRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerAttestationResultRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerAttestationResultResponseRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialCreationOptionsResponse
import com.huawei.hms.support.api.fido.fido2.Algorithm
import com.huawei.hms.support.api.fido.fido2.Attachment
import com.huawei.hms.support.api.fido.fido2.AttestationConveyancePreference
import com.huawei.hms.support.api.fido.fido2.AuthenticatorAssertionResponse
import com.huawei.hms.support.api.fido.fido2.AuthenticatorAttestationResponse
import com.huawei.hms.support.api.fido.fido2.AuthenticatorMetadata
import com.huawei.hms.support.api.fido.fido2.AuthenticatorSelectionCriteria
import com.huawei.hms.support.api.fido.fido2.AuthenticatorTransport
import com.huawei.hms.support.api.fido.fido2.Fido2Client
import com.huawei.hms.support.api.fido.fido2.Fido2Extension
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialCreationOptions
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialDescriptor
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialParameters
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialRequestOptions
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialRpEntity
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialType
import com.huawei.hms.support.api.fido.fido2.PublicKeyCredentialUserEntity
import com.huawei.hms.support.api.fido.fido2.UserVerificationRequirement

import java.io.UnsupportedEncodingException
import java.util.ArrayList
import java.util.HashMap

/**
 * Server Utilities
 *
 * @author Huawei HMS
 * @since 2020-03-08
 */
object ServerUtils {
    private val TAG = "ServerUtils"

    fun convert2PublicKeyCredentialCreationOptions(fido2Client: Fido2Client,
                                                   response: ServerPublicKeyCredentialCreationOptionsResponse): PublicKeyCredentialCreationOptions {
        val builder = PublicKeyCredentialCreationOptions.Builder()

        val name = response.rp!!.name
        val entity = PublicKeyCredentialRpEntity(name, name, null)
        builder.setRp(entity)

        val id = response.user!!.id
        try {
            builder.setUser(PublicKeyCredentialUserEntity(id, id!!.toByteArray(charset("UTF-8"))))
        } catch (e: UnsupportedEncodingException) {
            Log.e(TAG, e.message, e)
        }

        val challengeTmp = response.challenge;
        if (challengeTmp != null) {
            builder.setChallenge(ByteUtils.base642Byte(challengeTmp))
        }

        if (response.pubKeyCredParams != null) {
            val parameters = ArrayList<PublicKeyCredentialParameters>()
            val serverPublicKeyCredentialParameters = response.pubKeyCredParams
            for (param in serverPublicKeyCredentialParameters!!) {
                try {
                    val parameter = PublicKeyCredentialParameters(
                            PublicKeyCredentialType.PUBLIC_KEY, Algorithm.fromCode(param.alg))
                    parameters.add(parameter)
                } catch (e: Exception) {
                    Log.e(TAG, e.message, e)
                }

            }
            builder.setPubKeyCredParams(parameters)
        }

        if (response.excludeCredentials != null) {
            val descriptors = ArrayList<PublicKeyCredentialDescriptor>()
            val serverDescriptors = response.excludeCredentials
            for (desc in serverDescriptors!!) {
                val transports = ArrayList<AuthenticatorTransport>()
                if (desc.transports != null) {
                    try {
                        transports.add(AuthenticatorTransport.fromValue(desc.transports))
                    } catch (e: Exception) {
                        Log.e(TAG, e.message, e)
                    }

                }
                val descTmp = desc.id;
                if (descTmp != null) {
                    val descriptor = PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY, ByteUtils.base642Byte(descTmp)!!, transports)
                    descriptors.add(descriptor)
                }
            }
            builder.setExcludeList(descriptors)
        }

        var attachment: Attachment? = null
        if (response.authenticatorSelection != null) {
            val selectionCriteria = response.authenticatorSelection
            if (selectionCriteria!!.authenticatorAttachment != null) {
                try {
                    attachment = Attachment.fromValue(selectionCriteria.authenticatorAttachment!!)
                } catch (e: Exception) {
                    Log.e(TAG, e.message, e)
                }

            }

            val residentKey = selectionCriteria.isRequireResidentKey

            var requirement: UserVerificationRequirement? = null
            if (selectionCriteria.userVerification != null) {
                try {
                    requirement = UserVerificationRequirement.fromValue(selectionCriteria.userVerification!!)
                } catch (e: Exception) {
                    Log.e(TAG, e.message, e)
                }

            }

            val fido2Selection = AuthenticatorSelectionCriteria(attachment, residentKey, requirement)
            builder.setAuthenticatorSelection(fido2Selection)
        }

        // attestation
        if (response.attestation != null) {
            try {
                val preference = AttestationConveyancePreference.fromValue(response.attestation!!)
                builder.setAttestation(preference)
            } catch (e: Exception) {
                Log.e(TAG, e.message, e)
            }

        }

        val extensions = HashMap<String, Any>()
        if (response.getExtensions() != null) {
            extensions.putAll(response.getExtensions()!!)
        }

        // Specify a platform authenticator and related extension items. You can specify a platform
        // authenticator or not as needed.
        if (Attachment.PLATFORM == attachment) {
            useSelectedPlatformAuthenticator(fido2Client, extensions)
        }
        builder.setExtensions(extensions)


        builder.setTimeoutSeconds(response.timeout)
        return builder.build()
    }

    fun convert2PublicKeyCredentialRequestOptions(fido2Client: Fido2Client,
                                                  response: ServerPublicKeyCredentialCreationOptionsResponse,
                                                  isUseSelectedPlatformAuthenticator: Boolean): PublicKeyCredentialRequestOptions {
        val builder = PublicKeyCredentialRequestOptions.Builder()

        builder.setRpId(response.rpId)

        val challengeTmp = response.challenge
        if (challengeTmp != null) {
            builder.setChallenge(ByteUtils.base642Byte(challengeTmp))
        }
        val descriptors = response.allowCredentials
        if (descriptors != null) {
            val descriptorList = ArrayList<PublicKeyCredentialDescriptor>()
            for (descriptor in descriptors) {
                val transports = ArrayList<AuthenticatorTransport>()
                if (descriptor.transports != null) {
                    try {
                        transports.add(AuthenticatorTransport.fromValue(descriptor.transports))
                    } catch (e: Exception) {
                        Log.e(TAG, e.message, e)
                    }

                }

                val descId = descriptor.id
                if (descId != null) {
                    val desc = PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY, ByteUtils.base642Byte(descId)!!, transports)
                    descriptorList.add(desc)
                }
            }
            builder.setAllowList(descriptorList)
        }

        val extensions = HashMap<String, Any>()
        if (response.getExtensions() != null) {
            extensions.putAll(response.getExtensions()!!)
        }
        // Specify a platform authenticator and related extension items. You can specify a platform
        // authenticator or not as needed.
        if (isUseSelectedPlatformAuthenticator) {
            useSelectedPlatformAuthenticator(fido2Client, extensions)
        }
        builder.setExtensions(extensions)
        builder.setTimeoutSeconds(response.timeout)
        return builder.build()
    }

    fun convert2ServerAttestationResultRequest(authenticatorAttestationResponse: AuthenticatorAttestationResponse): ServerAttestationResultRequest {
        val request = ServerAttestationResultRequest()
        val attestationResponse = ServerAttestationResultResponseRequest()
        attestationResponse
                .attestationObject = ByteUtils.byte2base64(authenticatorAttestationResponse.attestationObject)
        attestationResponse
                .clientDataJSON = ByteUtils.byte2base64(authenticatorAttestationResponse.clientDataJson)
        request.response = attestationResponse
        request.id = ByteUtils.byte2base64(authenticatorAttestationResponse.credentialId)
        request.type = "public-key"
        return request
    }

    fun convert2ServerAssertionResultRequest(authenticatorAssertation: AuthenticatorAssertionResponse): ServerAssertionResultRequest {
        val assertionResultResponse = ServerAssertionResultResponseRequest()
        assertionResultResponse.signature = ByteUtils.byte2base64(authenticatorAssertation.signature)
        assertionResultResponse.clientDataJSON = ByteUtils.byte2base64(authenticatorAssertation.clientDataJson)
        assertionResultResponse
                .authenticatorData = ByteUtils.byte2base64(authenticatorAssertation.authenticatorData)

        val request = ServerAssertionResultRequest()
        request.response = assertionResultResponse

        request.id = ByteUtils.byte2base64(authenticatorAssertation.credentialId)

        request.type = "public-key"
        return request
    }

    // Specify a platform authenticator and related extension items.
    private fun useSelectedPlatformAuthenticator(fido2Client: Fido2Client,
                                                 extensions: HashMap<String, Any>) {
        if (!fido2Client.hasPlatformAuthenticators()) {
            return
        }
        val selectedAuthenticatorList = ArrayList<String>()
        for (meta in fido2Client.platformAuthenticators) {
            if (!meta.isAvailable) {
                continue
            }
            // Fingerprint authenticator
            if (meta.isSupportedUvm(AuthenticatorMetadata.UVM_FINGERPRINT)) {
                selectedAuthenticatorList.add(meta.aaguid)

                if (meta.extensions.contains(Fido2Extension.W3C_WEBAUTHN_UVI.identifier)) {
                    // Indicates whether to verify the fingerprint ID. If the value is true, the
                    // same finger must be used for both registration and verification.
                    extensions[Fido2Extension.W3C_WEBAUTHN_UVI.identifier] = java.lang.Boolean.TRUE
                }

                if (meta.extensions.contains(Fido2Extension.HMS_R_PA_CIBBE_01.identifier)) {
                    // Indicates whether the authentication credential expires when the biometric
                    // feature changes. If the value is true, the key will expire when the fingerprint
                    // is enrolled. This is valid only for registration.
                    extensions[Fido2Extension.HMS_R_PA_CIBBE_01.identifier] = java.lang.Boolean.TRUE
                }
            } else if (meta.isSupportedUvm(AuthenticatorMetadata.UVM_FACEPRINT)) {
                // selectedAuthenticatorList.add(meta.getAaguid());
                Log.i(TAG, "Lock screen 3D face authenticator")
            }// Lock screen 3D face authenticator
        }
        extensions[Fido2Extension.HMS_RA_C_PACL_01.identifier] = selectedAuthenticatorList
    }
}
