package dev.meloda.fast.data.interceptor

import dev.meloda.fast.data.UserConfig
import dev.meloda.fast.data.db.AccountsRepository
import kotlinx.coroutines.runBlocking

internal data class TokenSession(
    val userId: Long,
    val accessToken: String,
    val revision: Long
)

internal class TokenSessionStore(
    private val accountsRepository: AccountsRepository
) {

    fun current(): TokenSession? = synchronized(UserConfig) {
        if (!UserConfig.isLoggedIn() || UserConfig.userId != UserConfig.currentUserId) {
            return null
        }

        TokenSession(
            userId = UserConfig.userId,
            accessToken = UserConfig.accessToken,
            revision = UserConfig.sessionRevision
        )
    }

    fun exchangeToken(session: TokenSession): String? = runBlocking {
        accountsRepository.getAccountById(session.userId)
            ?.takeIf { it.accessToken == session.accessToken }
            ?.exchangeToken
    }

    fun save(session: TokenSession, token: String): TokenSession? = synchronized(UserConfig) {
        if (current() != session) return null

        runBlocking {
            val account = accountsRepository.getAccountById(session.userId) ?: return@runBlocking null
            if (account.accessToken != session.accessToken) return@runBlocking null

            accountsRepository.storeAccounts(listOf(account.copy(accessToken = token)))
            UserConfig.accessToken = token
            current()
        }
    }
}
