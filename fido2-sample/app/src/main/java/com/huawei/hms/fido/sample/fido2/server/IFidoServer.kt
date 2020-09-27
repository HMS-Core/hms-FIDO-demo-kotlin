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
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegDeleteRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfoRequest
import com.huawei.hms.fido.sample.fido2.server.param.ServerRegInfoResponse
import com.huawei.hms.fido.sample.fido2.server.param.ServerResponse

/**
 * Fido2 server service
 *
 * @author Huawei HMS
 * @since 2020-03-08
 */
interface IFidoServer {
    fun getAttestationOptions(request: ServerPublicKeyCredentialCreationOptionsRequest): ServerPublicKeyCredentialCreationOptionsResponse

    fun getAttestationResult(attestationResultRequest: ServerAttestationResultRequest): ServerResponse

    fun getAssertionOptions(
            serverPublicKeyCredentialCreationOptionsRequest: ServerPublicKeyCredentialCreationOptionsRequest): ServerPublicKeyCredentialCreationOptionsResponse

    fun getAssertionResult(assertionResultRequest: ServerAssertionResultRequest): ServerResponse

    fun getRegInfo(regInfoRequest: ServerRegInfoRequest): ServerRegInfoResponse

    fun delete(regDeleteRequest: ServerRegDeleteRequest): ServerResponse
}
