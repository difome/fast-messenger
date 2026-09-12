package dev.meloda.fast.data.interceptor

import dev.meloda.fast.common.AppConstants
import dev.meloda.fast.common.VkConstants
import dev.meloda.fast.data.db.AccountsRepository
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class TokenRefreshInterceptor(
    accountsRepository: AccountsRepository
) : Interceptor {

    private companion object {
        val REFRESH_RETRY_DELAY_NANOS = TimeUnit.SECONDS.toNanos(30)
        const val ERROR_BODY_LIMIT = 65_536L
    }

    private val sessions = TokenSessionStore(accountsRepository)
    private val refreshLock = Any()
    private var lastAttempt: TokenSession? = null
    private var lastResult: TokenSession? = null
    private var lastAttemptAt = 0L
    private val apiUrl = AppConstants.URL_API.toHttpUrl()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val session = sessions.current()
        val response = chain.proceed(request)
        if (session == null || !request.canRefresh(session) || !response.isTokenExpired()) {
            return response
        }

        val body = response.body ?: return response
        val error = response.newBuilder()
            .body(body.bytes().toResponseBody(body.contentType()))
            .build()
        response.close()

        val refreshed = synchronized(refreshLock) {
            val retryDelayed = System.nanoTime() - lastAttemptAt < REFRESH_RETRY_DELAY_NANOS

            if (lastAttempt == session && (lastResult != null || retryDelayed)) {
                lastResult?.takeIf { sessions.current() == it }
            } else if (sessions.current() != session) {
                null
            } else {
                lastAttempt = session
                lastAttemptAt = System.nanoTime()
                lastResult = null
                lastResult = runCatching {
                    val exchangeToken = sessions.exchangeToken(session)
                        ?.takeIf { it.isNotBlank() } ?: return@runCatching null
                    val token = refresh(chain, exchangeToken, session.userId)
                        ?: return@runCatching null
                    sessions.save(session, token)
                }.getOrNull()
                lastResult
            }
        }
        if (refreshed == null || sessions.current() != refreshed) return error

        error.close()
        return chain.proceed(request.withToken(refreshed.accessToken))
    }

    private fun Request.canRefresh(session: TokenSession): Boolean {
        if (url.scheme != apiUrl.scheme ||
            url.host != apiUrl.host ||
            url.port != apiUrl.port ||
            !url.encodedPath.startsWith(apiUrl.encodedPath.trimEnd('/') + "/") ||
            url.encodedPath.substringAfterLast('/').startsWith("auth.") ||
            body?.isOneShot() == true || body?.isDuplex() == true
        ) {
            return false
        }

        val tokens = url.queryParameterValues("access_token").toMutableList()
        (body as? FormBody)?.let { form ->
            for (i in 0 until form.size) {
                if (form.name(i) == "access_token") tokens.add(form.value(i))
            }
        }
        return tokens.isNotEmpty() && tokens.all { it == session.accessToken }
    }

    private fun Response.isTokenExpired(): Boolean {
        if (code == 401) return true

        return runCatching {
            val error = JSONObject(peekBody(ERROR_BODY_LIMIT).string()).optJSONObject("error")
            error?.optInt("error_code") in setOf(5, 1117)
        }.getOrDefault(false)
    }

    private fun refresh(
        chain: Interceptor.Chain,
        exchangeToken: String,
        userId: Long
    ): String? {
        val url = apiUrl.newBuilder()
            .addPathSegment("auth.refreshTokens")
            .addQueryParameter("v", AppConstants.API_VERSION)
            .build()
        val body = FormBody.Builder()
            .add("client_id", VkConstants.MESSENGER_APP_ID.toString())
            .add("client_secret", VkConstants.MESSENGER_APP_SECRET)
            .add("exchange_tokens", exchangeToken)
            .add("active_index", "0")
            .add("scope", "all")
            .build()
        val request = Request.Builder()
            .url(url)
            .post(body)
            .build()

        return chain.proceed(request).use { response ->
            if (!response.isSuccessful) return null
            val result = JSONObject(response.body?.string() ?: return null)
                .optJSONObject("response") ?: return null
            val errors = result.optJSONArray("errors")
            if (errors != null && errors.length() != 0) return null
            val success = result.optJSONArray("success") ?: return null
            if (success.length() != 1) return null
            val entry = success.getJSONObject(0)
            if (entry.optInt("index", -1) != 0 ||
                entry.optLong("user_id", -1) != userId ||
                entry.isEnabled("banned") ||
                entry.isEnabled("deactivated") ||
                entry.optJSONObject("silent_token") != null
            ) {
                return null
            }

            entry.optJSONObject("access_token")?.optString("token")?.takeIf { it.isNotBlank() }
        }
    }

    private fun JSONObject.isEnabled(name: String): Boolean =
        optBoolean(name) || optInt(name) == 1

    private fun Request.withToken(token: String): Request {
        val updatedUrl = url.newBuilder()
            .setQueryParameter("access_token", token)
            .build()
        val builder = newBuilder().url(updatedUrl)

        (body as? FormBody)?.let { form ->
            val updated = FormBody.Builder()
            for (i in 0 until form.size) {
                val name = form.name(i)
                val value = if (name == "access_token") token else form.value(i)
                updated.add(name, value)
            }
            builder.method(method, updated.build())
        }
        return builder.build()
    }
}
