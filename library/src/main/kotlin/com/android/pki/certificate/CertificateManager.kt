package com.android.pki.certificate

import okhttp3.OkHttpClient
import org.slf4j.LoggerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

/**
 * Main class for PKI Certificate Management with AWS Private CA Integration
 */
class CertificateManager(
    private val retryConfig: RetryConfig = RetryConfig()
) {
    
    companion object {
        private val logger = LoggerFactory.getLogger(CertificateManager::class.java)
    }

    private val keyAndCsrManager = KeyAndCsrManager()
    private val awsPrivateCaClient = AwsPrivateCaClient(retryConfig)
    private val certificateStorage = CertificateStorage()

    /**
     * Generate key pair and CSR, then request certificate from AWS Private CA
     * @param subject Subject information for the certificate
     * @param caEndpoint AWS Private CA endpoint
     * @param authToken Authentication token for AWS Private CA
     * @return Result containing certificate info or error
     */
    suspend fun requestCertificate(
        subject: CertificateSubject,
        caEndpoint: String,
        authToken: String
    ): CertificateResult<CertificateInfo> {
        logger.info("Starting certificate request process for subject: ${subject.toX500Name()}")
        
        try {
            // Generate key pair and CSR
            val keyPairAndCsrResult = keyAndCsrManager.generateKeyPairAndCsr(subject)
            if (keyPairAndCsrResult is CertificateResult.Error) {
                return keyPairAndCsrResult
            }
            
            val (keyPair, csr) = (keyPairAndCsrResult as CertificateResult.Success).data
            
            // Encode CSR to PEM format
            val csrPemResult = keyAndCsrManager.encodeCsrToPem(csr)
            if (csrPemResult is CertificateResult.Error) {
                return csrPemResult
            }
            
            val csrPem = (csrPemResult as CertificateResult.Success).data
            
            // Request certificate from AWS Private CA
            val certificateResult = awsPrivateCaClient.requestCertificate(csrPem, caEndpoint, authToken)
            if (certificateResult is CertificateResult.Error) {
                return certificateResult
            }
            
            val certificate = (certificateResult as CertificateResult.Success).data
            
            // Generate alias for storage
            val alias = generateAlias(subject)
            
            // Store certificate and private key
            val storeResult = certificateStorage.storeCertificate(alias, certificate, keyPair.private)
            if (storeResult is CertificateResult.Error) {
                return storeResult
            }
            
            // Return certificate info
            val certInfo = certificateStorage.getCertificateInfo(alias)
                ?: return CertificateResult.Error("Failed to retrieve stored certificate info")
            
            logger.info("Certificate request completed successfully for alias: $alias")
            return CertificateResult.Success(certInfo)
            
        } catch (e: Exception) {
            logger.error("Certificate request failed", e)
            return CertificateResult.Error("Certificate request failed: ${e.message}", e)
        }
    }

    /**
     * Get stored certificate for use with HTTPS client
     * @param alias The alias of the stored certificate
     * @return KeyManager that can be used with SSLContext, or null if not found
     */
    fun getKeyManager(alias: String): X509KeyManager? {
        logger.debug("Getting KeyManager for alias: $alias")
        return certificateStorage.getKeyManager(alias)
    }

    /**
     * Check if a certificate exists and is valid
     * @param alias The alias to check
     * @return true if certificate exists and is valid
     */
    fun hasCertificate(alias: String): Boolean {
        logger.debug("Checking certificate existence for alias: $alias")
        return certificateStorage.hasCertificate(alias)
    }

    /**
     * Get certificate information
     * @param alias The alias of the stored certificate
     * @return Certificate information or null if not found
     */
    fun getCertificateInfo(alias: String): CertificateInfo? {
        logger.debug("Getting certificate info for alias: $alias")
        return certificateStorage.getCertificateInfo(alias)
    }

    /**
     * Configure OkHttpClient with the certificate for client authentication
     * @param alias The alias of the stored certificate
     * @param builder OkHttpClient.Builder to configure
     * @return Configured OkHttpClient.Builder or null if certificate not found
     */
    fun configureOkHttpClient(alias: String, builder: OkHttpClient.Builder): OkHttpClient.Builder? {
        logger.debug("Configuring OkHttpClient for alias: $alias")
        
        val keyManager = getKeyManager(alias) ?: return null
        
        return try {
            // Create SSL context with our key manager
            val sslContext = SSLContext.getInstance("TLS")
            
            // Use default trust manager
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as java.security.KeyStore?)
            val trustManagers = trustManagerFactory.trustManagers
            val trustManager = trustManagers.firstOrNull { it is X509TrustManager } as? X509TrustManager
                ?: throw IllegalStateException("No X509TrustManager found")
            
            sslContext.init(arrayOf(keyManager), arrayOf(trustManager), null)
            
            builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            
            logger.debug("OkHttpClient configured successfully for alias: $alias")
            builder
        } catch (e: Exception) {
            logger.error("Failed to configure OkHttpClient for alias: $alias", e)
            null
        }
    }

    /**
     * Remove a certificate from storage
     * @param alias The alias of the certificate to remove
     * @return Result indicating success or failure
     */
    fun removeCertificate(alias: String): CertificateResult<Unit> {
        logger.info("Removing certificate with alias: $alias")
        return certificateStorage.removeCertificate(alias)
    }

    /**
     * List all stored certificate aliases
     * @return List of certificate aliases
     */
    fun listCertificates(): List<String> {
        logger.debug("Listing all certificate aliases")
        return certificateStorage.listAliases()
    }

    /**
     * Get all certificate information for stored certificates
     * @return List of certificate information for all stored certificates
     */
    fun getAllCertificateInfo(): List<CertificateInfo> {
        return listCertificates().mapNotNull { alias ->
            getCertificateInfo(alias)
        }
    }

    /**
     * Generate a unique alias for certificate storage based on the subject
     */
    private fun generateAlias(subject: CertificateSubject): String {
        val timestamp = System.currentTimeMillis()
        val commonName = subject.commonName.replace("[^a-zA-Z0-9]".toRegex(), "_")
        return "cert_${commonName}_$timestamp"
    }
}