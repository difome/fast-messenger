package dev.meloda.fast.data.interceptor

import dev.meloda.fast.common.AppConstants
import dev.meloda.fast.common.VkConstants
import dev.meloda.fast.data.UserConfig
import dev.meloda.fast.data.db.AccountsRepository
import dev.meloda.fast.logger.FastLogger
import kotlinx.coroutines.runBlocking
import okhttp3.FormBody
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject

class TokenRefreshInterceptor(
    private val accountsRepository: AccountsRepository,
    private val logger: FastLogger
) : Interceptor {

    private val refreshLock = Any()

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val originalResponse = chain.proceed(originalRequest)

        if (!isTokenExpiredResponse(originalResponse)) {
            return originalResponse
        }

        synchronized(refreshLock) {
            val currentToken = UserConfig.accessToken
            val requestToken = originalRequest.url.queryParameter("access_token")

            if (currentToken.isNotBlank() && currentToken != requestToken) {
                originalResponse.close()
                return chain.proceed(originalRequest.withNewToken(currentToken))
            }

            logger.debug(this::class, "Token expired. Attempting refresh...")

            val newToken = refreshToken(chain)
            if (!newToken.isNullOrBlank()) {
                logger.debug(this::class, "Token refreshed successfully.")
                originalResponse.close()
                return chain.proceed(originalRequest.withNewToken(newToken))
            } else {
                logger.error(this::class, "Token refresh failed.")
            }
        }

        return originalResponse
    }

    private fun isTokenExpiredResponse(response: Response): Boolean {
        if (!response.isSuccessful && response.code == 401) {
            return true
        }

        val peekBody = runCatching { response.peekBody(8192).string() }.getOrNull() ?: return false
        if (!peekBody.contains("error")) return false

        return try {
            val json = JSONObject(peekBody)
            if (json.has("error")) {
                val errorObj = json.optJSONObject("error")
                val errorCode = errorObj?.optInt("error_code", -1) ?: -1
                errorCode == 5 || errorCode == 1117
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun refreshToken(chain: Interceptor.Chain): String? {
        val oldToken = UserConfig.accessToken
        if (oldToken.isBlank()) return null

        val refreshUrl = "${AppConstants.URL_API}/auth.getExchangeToken"
        val requestBody = FormBody.Builder()
            .add("access_token", oldToken)
            .add("v", VkConstants.LP_VERSION.toString())
            .build()

        val refreshRequest = Request.Builder()
            .url(refreshUrl)
            .post(requestBody)
            .build()

        return try {
            val response = chain.proceed(refreshRequest)
            if (!response.isSuccessful) {
                response.close()
                return null
            }

            val responseString = response.body?.string().orEmpty()
            response.close()

            val json = JSONObject(responseString)
            val responseObj = json.optJSONObject("response") ?: return null
            val usersTokens = responseObj.optJSONArray("users_exchange_tokens") ?: return null

            var newCommonToken: String? = null
            for (i in 0 until usersTokens.length()) {
                val item = usersTokens.getJSONObject(i)
                val token = item.optString("common_token", item.optString("access_token", ""))
                if (token.isNotBlank()) {
                    newCommonToken = token
                    break
                }
            }

            if (!newCommonToken.isNullOrBlank()) {
                UserConfig.accessToken = newCommonToken

                val currentUserId = UserConfig.currentUserId
                if (currentUserId > 0) {
                    runBlocking {
                        val currentAccount = accountsRepository.getAccountById(currentUserId)
                        if (currentAccount != null) {
                            val updatedAccount = currentAccount.copy(accessToken = newCommonToken)
                            accountsRepository.storeAccounts(listOf(updatedAccount))
                        }
                    }
                }
                newCommonToken
            } else {
                null
            }
        } catch (e: Exception) {
            logger.error(this::class, "Exception during token refresh", e)
            null
        }
    }

    private fun Request.withNewToken(newToken: String): Request {
        val newUrl = url.newBuilder()
            .setQueryParameter("access_token", newToken)
            .build()

        return newBuilder()
            .url(newUrl)
            .build()
    }
}
