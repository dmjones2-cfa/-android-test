package com.android.pki.certificate

import kotlinx.coroutines.delay
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMParser
import org.json.JSONObject
import org.slf4j.LoggerFactory
import java.io.StringReader
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

/**
 * Client for interacting with AWS Private CA
 */
class AwsPrivateCaClient(
    private val retryConfig: RetryConfig = RetryConfig()
) {
    
    companion object {
        private val logger = LoggerFactory.getLogger(AwsPrivateCaClient::class.java)
        private val JSON_MEDIA_TYPE = "application/json".toMediaType()
        private const val CONNECT_TIMEOUT_SECONDS = 30L
        private const val READ_TIMEOUT_SECONDS = 60L
        private const val WRITE_TIMEOUT_SECONDS = 60L
    }

    private val httpClient: OkHttpClient by lazy {
        val loggingInterceptor = HttpLoggingInterceptor { message ->
            logger.debug("HTTP: $message")
        }.apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }

        OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Submit CSR to AWS Private CA and get signed certificate
     */
    suspend fun requestCertificate(
        csrPem: String,
        caEndpoint: String,
        authToken: String
    ): CertificateResult<X509Certificate> {
        logger.info("Requesting certificate from AWS Private CA: $caEndpoint")
        
        return withRetry { attempt ->
            try {
                val requestBody = createCertificateRequestBody(csrPem)
                val request = Request.Builder()
                    .url(caEndpoint)
                    .post(requestBody)
                    .addHeader("Authorization", "Bearer $authToken")
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Accept", "application/json")
                    .build()

                logger.debug("Sending certificate request (attempt ${attempt + 1})")
                
                val response = httpClient.newCall(request).execute()
                
                if (!response.isSuccessful) {
                    val errorBody = response.body?.string() ?: "Unknown error"
                    val message = "Certificate request failed with status ${response.code}: $errorBody"
                    logger.warn(message)
                    throw CertificateRequestException(message, response.code)
                }

                val responseBody = response.body?.string()
                    ?: throw CertificateRequestException("Empty response body", response.code)

                val certificate = parseCertificateResponse(responseBody)
                logger.info("Certificate received successfully")
                
                CertificateResult.Success(certificate)
            } catch (e: CertificateRequestException) {
                if (e.statusCode in 400..499) {
                    // Client errors shouldn't be retried
                    logger.error("Client error (${e.statusCode}), not retrying: ${e.message}")
                    CertificateResult.Error("Certificate request failed: ${e.message}", e)
                } else {
                    // Server errors can be retried
                    throw e
                }
            } catch (e: Exception) {
                logger.warn("Certificate request failed (attempt ${attempt + 1}): ${e.message}")
                throw e
            }
        }
    }

    /**
     * Create JSON request body for certificate request
     */
    private fun createCertificateRequestBody(csrPem: String): RequestBody {
        val json = JSONObject().apply {
            put("CertificateSigningRequest", csrPem)
            put("SigningAlgorithm", "SHA256WITHRSA")
            put("Validity", JSONObject().apply {
                put("Type", "DAYS")
                put("Value", 365)
            })
        }
        
        return json.toString().toRequestBody(JSON_MEDIA_TYPE)
    }

    /**
     * Parse certificate from AWS Private CA response
     */
    private fun parseCertificateResponse(responseBody: String): X509Certificate {
        try {
            val json = JSONObject(responseBody)
            val certificatePem = json.getString("Certificate")
            
            return parsePemCertificate(certificatePem)
        } catch (e: Exception) {
            logger.error("Failed to parse certificate response", e)
            throw CertificateRequestException("Failed to parse certificate response: ${e.message}")
        }
    }

    /**
     * Parse PEM formatted certificate string to X509Certificate
     */
    private fun parsePemCertificate(certificatePem: String): X509Certificate {
        try {
            val pemParser = PEMParser(StringReader(certificatePem))
            val certificateHolder = pemParser.readObject() as X509CertificateHolder
            pemParser.close()
            
            return JcaX509CertificateConverter().getCertificate(certificateHolder)
        } catch (e: Exception) {
            logger.error("Failed to parse PEM certificate", e)
            throw CertificateRequestException("Failed to parse PEM certificate: ${e.message}")
        }
    }

    /**
     * Execute operation with retry logic and exponential backoff
     */
    private suspend fun <T> withRetry(
        operation: suspend (attempt: Int) -> CertificateResult<T>
    ): CertificateResult<T> {
        var lastException: Exception? = null
        
        repeat(retryConfig.maxAttempts) { attempt ->
            try {
                val result = operation(attempt)
                if (result is CertificateResult.Success) {
                    return result
                } else if (result is CertificateResult.Error) {
                    // If operation returns error result, don't retry
                    return result
                }
            } catch (e: Exception) {
                lastException = e
                logger.warn("Attempt ${attempt + 1} failed: ${e.message}")
                
                if (attempt < retryConfig.maxAttempts - 1) {
                    val delayMs = retryConfig.calculateDelay(attempt)
                    logger.info("Retrying in ${delayMs}ms...")
                    delay(delayMs)
                }
            }
        }
        
        val message = "All ${retryConfig.maxAttempts} attempts failed"
        logger.error(message, lastException)
        return CertificateResult.Error(message, lastException)
    }

    /**
     * Custom exception for certificate request errors
     */
    class CertificateRequestException(
        message: String,
        val statusCode: Int = 0,
        cause: Throwable? = null
    ) : Exception(message, cause)
}