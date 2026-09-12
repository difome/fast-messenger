package dev.meloda.fast.data

import dev.meloda.fast.datastore.AppSettings

object UserConfig {

    private const val ARG_CURRENT_USER_ID = "current_user_id"

    internal var sessionRevision: Long = 0
        private set

    @get:Synchronized
    @set:Synchronized
    var currentUserId: Long = -1
        get() = AppSettings.getLong(ARG_CURRENT_USER_ID, -1)
        set(value) {
            sessionRevision++
            field = value
            AppSettings.edit { putLong(ARG_CURRENT_USER_ID, value) }
        }

    @get:Synchronized
    @set:Synchronized
    var userId: Long = -1
        set(value) {
            sessionRevision++
            field = value
        }

    @get:Synchronized
    @set:Synchronized
    var accessToken: String = ""
        set(value) {
            sessionRevision++
            field = value
        }

    var fastToken: String? = ""
    var trustedHash: String? = null
    var exchangeToken: String? = null

    @Synchronized
    fun clear() {
        currentUserId = -1
        accessToken = ""
        fastToken = ""
        userId = -1
    }

    @Synchronized
    fun isLoggedIn(): Boolean {
        return currentUserId > 0 && userId > 0 && accessToken.isNotBlank()
    }
}
