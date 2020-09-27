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

import com.huawei.hms.fido.sample.fido2.server.param.ServerAssertionResultRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerAttestationResultRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialCreationOptionsRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialCreationOptionsResponse
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialDescriptor
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialParameters
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialRpEntity
import com.huawei.hms.fido.sample.fido2.server.param.ServerPublicKeyCredentialUserEntity
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegDeleteRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfo
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfoRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfoResponse
import com.huawei.hms.fido.sample.fido2.server.param.ServerResponse

import java.security.SecureRandom
import java.util.ArrayList

/**
 * Simulating a Fido Server
 *
 * @author Huawei HMS
 * @since 2020-03-08
 */
class FidoServerSimulator : IFidoServer {

    override fun getAttestationOptions(request: ServerPublicKeyCredentialCreationOptionsRequest): ServerPublicKeyCredentialCreationOptionsResponse {
        val response = ServerPublicKeyCredentialCreationOptionsResponse()
        response.attestation = request.attestation

        val selectionCriteria = request.authenticatorSelection
        if (selectionCriteria != null) {
            response.authenticatorSelection = selectionCriteria
        }

        response.challenge = ByteUtils.byte2base64(challege)

        val excludeCredentialList = ArrayList<ServerPublicKeyCredentialDescriptor>()
        for (info in regInfos) {
            val desc = ServerPublicKeyCredentialDescriptor()
            desc.id = info.credentialId
            desc.type = "public-key"
            excludeCredentialList.add(desc)
        }
        response.excludeCredentials = excludeCredentialList.toTypedArray<ServerPublicKeyCredentialDescriptor>()

        val pubKeyCredParamList = ArrayList<ServerPublicKeyCredentialParameters>()
        var cp = ServerPublicKeyCredentialParameters()
        cp.alg = -7
        cp.type = "public-key"
        pubKeyCredParamList.add(cp)
        cp = ServerPublicKeyCredentialParameters()
        cp.alg = -257
        cp.type = "public-key"
        pubKeyCredParamList.add(cp)
        response.pubKeyCredParams = pubKeyCredParamList.toTypedArray<ServerPublicKeyCredentialParameters>()

        val rpEntity = ServerPublicKeyCredentialRpEntity()
        rpEntity.name = "www.huawei.fidodemo"
        response.rp = rpEntity

        response.rpId = "www.huawei.fidodemo"

        response.timeout = 60L
        val user = ServerPublicKeyCredentialUserEntity()
        user.id = request.username
        user.displayName = request.displayName
        response.user = user
        return response
    }

    override fun getAttestationResult(attestationResultRequest: ServerAttestationResultRequest): ServerResponse {
        val response = ServerResponse()
        val info = ServerRegInfo()
        info.credentialId = attestationResultRequest.id
        regInfos.add(info)
        return response
    }

    override fun getAssertionOptions(
            serverPublicKeyCredentialCreationOptionsRequest: ServerPublicKeyCredentialCreationOptionsRequest): ServerPublicKeyCredentialCreationOptionsResponse {
        val response = ServerPublicKeyCredentialCreationOptionsResponse()

        val allowCredentials = ArrayList<ServerPublicKeyCredentialDescriptor>()
        for (info in regInfos) {
            val desc = ServerPublicKeyCredentialDescriptor()
            desc.id = info.credentialId
            desc.type = "public-key"
            allowCredentials.add(desc)
        }
        response.allowCredentials = allowCredentials.toTypedArray<ServerPublicKeyCredentialDescriptor>()

        response.challenge = ByteUtils.byte2base64(challege)

        response.rpId = "www.huawei.fidodemo"

        response.timeout = 60L

        return response
    }

    override fun getAssertionResult(assertionResultRequest: ServerAssertionResultRequest): ServerResponse {
        return ServerResponse()
    }

    override fun getRegInfo(regInfoRequest: ServerRegInfoRequest): ServerRegInfoResponse {
        val response = ServerRegInfoResponse()
        val infos = ArrayList<ServerRegInfo>()
        for (regInfo in regInfos) {
            val info = ServerRegInfo()
            info.credentialId = regInfo.credentialId
            infos.add(info)
        }
        response.infos = infos
        return response
    }

    override fun delete(regDeleteRequest: ServerRegDeleteRequest): ServerResponse {
        val response = ServerResponse()
        regInfos.clear()
        return response
    }

    companion object {
        private val regInfos = ArrayList<ServerRegInfo>()

        private val challege: ByteArray
            get() = SecureRandom.getSeed(16)
    }
}
