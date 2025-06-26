package com.android.pki.certificate

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.slf4j.LoggerFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom

/**
 * Handles key generation and Certificate Signing Request (CSR) creation
 */
class KeyAndCsrManager {
    
    companion object {
        private val logger = LoggerFactory.getLogger(KeyAndCsrManager::class.java)
        private const val KEY_ALGORITHM = "RSA"
        private const val KEY_SIZE = 2048
        private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
    }

    /**
     * Generate a new RSA key pair with default parameters
     */
    fun generateKeyPair(): CertificateResult<KeyPair> {
        return try {
            logger.info("Generating RSA key pair with size $KEY_SIZE")
            
            val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
            keyPairGenerator.initialize(KEY_SIZE, SecureRandom())
            val keyPair = keyPairGenerator.generateKeyPair()
            
            logger.info("Key pair generated successfully")
            CertificateResult.Success(keyPair)
        } catch (e: Exception) {
            logger.error("Failed to generate key pair", e)
            CertificateResult.Error("Failed to generate key pair: ${e.message}", e)
        }
    }

    /**
     * Create a Certificate Signing Request (CSR) for the given key pair and subject
     */
    fun createCsr(
        keyPair: KeyPair,
        subject: CertificateSubject
    ): CertificateResult<PKCS10CertificationRequest> {
        return try {
            logger.info("Creating CSR for subject: ${subject.toX500Name()}")
            
            val x500Name = X500Name(subject.toX500Name())
            val csrBuilder = JcaPKCS10CertificationRequestBuilder(x500Name, keyPair.public)
            
            val contentSigner = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(keyPair.private)
            
            val csr = csrBuilder.build(contentSigner)
            
            logger.info("CSR created successfully")
            CertificateResult.Success(csr)
        } catch (e: Exception) {
            logger.error("Failed to create CSR", e)
            CertificateResult.Error("Failed to create CSR: ${e.message}", e)
        }
    }

    /**
     * Encode CSR as PEM format string
     */
    fun encodeCsrToPem(csr: PKCS10CertificationRequest): CertificateResult<String> {
        return try {
            val base64 = java.util.Base64.getEncoder().encodeToString(csr.encoded)
            val pem = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    base64.chunked(64).joinToString("\n") +
                    "\n-----END CERTIFICATE REQUEST-----"
            
            CertificateResult.Success(pem)
        } catch (e: Exception) {
            logger.error("Failed to encode CSR to PEM", e)
            CertificateResult.Error("Failed to encode CSR to PEM: ${e.message}", e)
        }
    }

    /**
     * Generate key pair and create CSR in one operation
     */
    fun generateKeyPairAndCsr(subject: CertificateSubject): CertificateResult<Pair<KeyPair, PKCS10CertificationRequest>> {
        val keyPairResult = generateKeyPair()
        if (keyPairResult is CertificateResult.Error) {
            return keyPairResult
        }
        
        val keyPair = (keyPairResult as CertificateResult.Success).data
        val csrResult = createCsr(keyPair, subject)
        
        return when (csrResult) {
            is CertificateResult.Success -> CertificateResult.Success(keyPair to csrResult.data)
            is CertificateResult.Error -> csrResult
        }
    }
}