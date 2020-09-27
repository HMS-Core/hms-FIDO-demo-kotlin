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

import android.util.Base64
import android.util.Log

/**
 * Byte Utilities
 *
 * @author Huawei HMS
 * @since 2020-03-08
 */
object ByteUtils {
    private val TAG = "ByteUtils"

    fun base642Byte(base64: String): ByteArray? {
        try {
            return Base64.decode(base64, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, e.message, e)
            return null
        }

    }

    fun byte2base64(raw: ByteArray): String {
        return Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}
