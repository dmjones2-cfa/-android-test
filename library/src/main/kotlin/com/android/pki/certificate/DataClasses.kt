package com.android.pki.certificate

import java.util.Date

/**
 * Certificate subject information for generating certificates
 */
data class CertificateSubject(
    val commonName: String,
    val organization: String? = null,
    val organizationalUnit: String? = null,
    val locality: String? = null,
    val state: String? = null,
    val country: String? = null
) {
    /**
     * Convert to X.500 Distinguished Name format
     */
    fun toX500Name(): String {
        val components = mutableListOf<String>()
        
        components.add("CN=$commonName")
        organization?.let { components.add("O=$it") }
        organizationalUnit?.let { components.add("OU=$it") }
        locality?.let { components.add("L=$it") }
        state?.let { components.add("ST=$it") }
        country?.let { components.add("C=$it") }
        
        return components.joinToString(", ")
    }
}

/**
 * Information about a stored certificate
 */
data class CertificateInfo(
    val alias: String,
    val subject: String,
    val issuer: String,
    val notBefore: Date,
    val notAfter: Date,
    val serialNumber: String
) {
    /**
     * Check if the certificate is currently valid (not expired)
     */
    fun isValid(): Boolean {
        val now = Date()
        return now.after(notBefore) && now.before(notAfter)
    }
}

/**
 * Configuration for retry behavior when communicating with AWS Private CA
 */
data class RetryConfig(
    val maxAttempts: Int = 5,
    val initialDelayMs: Long = 1000,
    val maxDelayMs: Long = 60000,
    val backoffFactor: Double = 1.5
) {
    init {
        require(maxAttempts > 0) { "maxAttempts must be greater than 0" }
        require(initialDelayMs > 0) { "initialDelayMs must be greater than 0" }
        require(maxDelayMs >= initialDelayMs) { "maxDelayMs must be >= initialDelayMs" }
        require(backoffFactor > 1.0) { "backoffFactor must be greater than 1.0" }
    }
    
    /**
     * Calculate delay for a given attempt (0-based)
     */
    fun calculateDelay(attempt: Int): Long {
        val delay = (initialDelayMs * Math.pow(backoffFactor, attempt.toDouble())).toLong()
        return minOf(delay, maxDelayMs)
    }
}

/**
 * Result wrapper for certificate operations
 */
sealed class CertificateResult<out T> {
    data class Success<out T>(val data: T) : CertificateResult<T>()
    data class Error(val message: String, val cause: Throwable? = null) : CertificateResult<Nothing>()
    
    inline fun <R> map(transform: (T) -> R): CertificateResult<R> = when (this) {
        is Success -> Success(transform(data))
        is Error -> this
    }
    
    inline fun onSuccess(action: (T) -> Unit): CertificateResult<T> {
        if (this is Success) action(data)
        return this
    }
    
    inline fun onError(action: (String, Throwable?) -> Unit): CertificateResult<T> {
        if (this is Error) action(message, cause)
        return this
    }
}