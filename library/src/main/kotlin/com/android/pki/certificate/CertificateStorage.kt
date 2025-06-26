package com.android.pki.certificate

import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509KeyManager

/**
 * Mock implementation of certificate storage that simulates Android Keystore behavior.
 * In a real Android environment, this would use the Android Keystore System.
 */
class CertificateStorage {
    
    companion object {
        private val logger = LoggerFactory.getLogger(CertificateStorage::class.java)
        private const val KEYSTORE_TYPE = "PKCS12"
        private const val KEYSTORE_PASSWORD = "changeit" // In real Android, this would be handled by the system
    }

    // Mock storage - in real Android this would be the Keystore system
    private val certificates = ConcurrentHashMap<String, StoredCertificate>()
    
    /**
     * Data class to hold certificate and private key together
     */
    private data class StoredCertificate(
        val certificate: X509Certificate,
        val privateKey: PrivateKey,
        val alias: String
    )

    /**
     * Store certificate and private key in the keystore
     */
    fun storeCertificate(
        alias: String,
        certificate: X509Certificate,
        privateKey: PrivateKey
    ): CertificateResult<Unit> {
        return try {
            logger.info("Storing certificate with alias: $alias")
            
            // In real Android implementation, this would use Android Keystore
            certificates[alias] = StoredCertificate(certificate, privateKey, alias)
            
            logger.info("Certificate stored successfully with alias: $alias")
            CertificateResult.Success(Unit)
        } catch (e: Exception) {
            logger.error("Failed to store certificate", e)
            CertificateResult.Error("Failed to store certificate: ${e.message}", e)
        }
    }

    /**
     * Check if a certificate exists and is valid
     */
    fun hasCertificate(alias: String): Boolean {
        val info = getCertificateInfo(alias) ?: return false
        return info.isValid()
    }

    /**
     * Get certificate information
     */
    fun getCertificateInfo(alias: String): CertificateInfo? {
        val stored = certificates[alias] ?: return null
        val cert = stored.certificate
        
        return try {
            CertificateInfo(
                alias = alias,
                subject = cert.subjectX500Principal.name,
                issuer = cert.issuerX500Principal.name,
                notBefore = cert.notBefore,
                notAfter = cert.notAfter,
                serialNumber = cert.serialNumber.toString()
            )
        } catch (e: Exception) {
            logger.error("Failed to extract certificate info for alias: $alias", e)
            null
        }
    }

    /**
     * Get KeyManager for HTTPS client authentication
     */
    fun getKeyManager(alias: String): X509KeyManager? {
        val stored = certificates[alias] ?: return null
        
        return try {
            // Create a temporary KeyStore to hold our certificate
            val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
            keyStore.load(null, null)
            
            // Store the certificate and private key
            keyStore.setKeyEntry(
                alias,
                stored.privateKey,
                KEYSTORE_PASSWORD.toCharArray(),
                arrayOf(stored.certificate)
            )
            
            // Create KeyManagerFactory
            val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray())
            
            // Return the first X509KeyManager
            keyManagerFactory.keyManagers
                .filterIsInstance<X509KeyManager>()
                .firstOrNull()
                ?.let { CustomX509KeyManager(it, alias) }
                
        } catch (e: Exception) {
            logger.error("Failed to create KeyManager for alias: $alias", e)
            null
        }
    }

    /**
     * Get the stored certificate directly
     */
    fun getCertificate(alias: String): X509Certificate? {
        return certificates[alias]?.certificate
    }

    /**
     * Get the stored private key directly
     */
    fun getPrivateKey(alias: String): PrivateKey? {
        return certificates[alias]?.privateKey
    }

    /**
     * Remove a certificate from storage
     */
    fun removeCertificate(alias: String): CertificateResult<Unit> {
        return try {
            certificates.remove(alias)
            logger.info("Certificate with alias '$alias' removed")
            CertificateResult.Success(Unit)
        } catch (e: Exception) {
            logger.error("Failed to remove certificate with alias: $alias", e)
            CertificateResult.Error("Failed to remove certificate: ${e.message}", e)
        }
    }

    /**
     * List all stored certificate aliases
     */
    fun listAliases(): List<String> {
        return certificates.keys.toList()
    }

    /**
     * Custom X509KeyManager that filters to only return our specific certificate
     */
    private class CustomX509KeyManager(
        private val delegate: X509KeyManager,
        private val targetAlias: String
    ) : X509KeyManager {
        
        override fun getClientAliases(keyType: String?, issuers: Array<out java.security.Principal>?): Array<String>? {
            return delegate.getClientAliases(keyType, issuers)?.filter { it == targetAlias }?.toTypedArray()
        }

        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out java.security.Principal>?, socket: java.net.Socket?): String? {
            return targetAlias
        }

        override fun getServerAliases(keyType: String?, issuers: Array<out java.security.Principal>?): Array<String>? {
            return delegate.getServerAliases(keyType, issuers)
        }

        override fun chooseServerAlias(keyType: String?, issuers: Array<out java.security.Principal>?, socket: java.net.Socket?): String? {
            return delegate.chooseServerAlias(keyType, issuers, socket)
        }

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
            return if (alias == targetAlias) delegate.getCertificateChain(alias) else null
        }

        override fun getPrivateKey(alias: String?): PrivateKey? {
            return if (alias == targetAlias) delegate.getPrivateKey(alias) else null
        }
    }
}