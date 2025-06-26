package com.android.pki.certificate

import org.junit.Test
import org.junit.Assert.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class KeyAndCsrManagerTest {

    companion object {
        init {
            // Add BouncyCastle provider for testing
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val keyAndCsrManager = KeyAndCsrManager()

    @Test
    fun `generateKeyPair should return success with valid key pair`() {
        val result = keyAndCsrManager.generateKeyPair()
        
        assertTrue(result is CertificateResult.Success)
        val keyPair = (result as CertificateResult.Success).data
        assertNotNull(keyPair.private)
        assertNotNull(keyPair.public)
        assertEquals("RSA", keyPair.private.algorithm)
        assertEquals("RSA", keyPair.public.algorithm)
    }

    @Test
    fun `createCsr should return success with valid CSR`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        val subject = CertificateSubject(
            commonName = "test.example.com",
            organization = "Test Org"
        )
        
        val csrResult = keyAndCsrManager.createCsr(keyPair, subject)
        
        assertTrue(csrResult is CertificateResult.Success)
        val csr = (csrResult as CertificateResult.Success).data
        assertNotNull(csr)
        assertTrue(csr.subject.toString().contains("CN=test.example.com"))
        assertTrue(csr.subject.toString().contains("O=Test Org"))
    }

    @Test
    fun `encodeCsrToPem should return valid PEM format`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        val subject = CertificateSubject(commonName = "test.example.com")
        val csrResult = keyAndCsrManager.createCsr(keyPair, subject)
        assertTrue(csrResult is CertificateResult.Success)
        val csr = (csrResult as CertificateResult.Success).data
        
        val pemResult = keyAndCsrManager.encodeCsrToPem(csr)
        
        assertTrue(pemResult is CertificateResult.Success)
        val pem = (pemResult as CertificateResult.Success).data
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        assertTrue(pem.endsWith("-----END CERTIFICATE REQUEST-----"))
        assertTrue(pem.contains("\n"))
    }

    @Test
    fun `generateKeyPairAndCsr should return both key pair and CSR`() {
        val subject = CertificateSubject(
            commonName = "test.example.com",
            organization = "Test Org"
        )
        
        val result = keyAndCsrManager.generateKeyPairAndCsr(subject)
        
        assertTrue(result is CertificateResult.Success)
        val (keyPair, csr) = (result as CertificateResult.Success).data
        
        assertNotNull(keyPair.private)
        assertNotNull(keyPair.public)
        assertNotNull(csr)
        assertTrue(csr.subject.toString().contains("CN=test.example.com"))
    }

    @Test
    fun `CSR should contain correct subject information`() {
        val subject = CertificateSubject(
            commonName = "api.example.com",
            organization = "Example Corp",
            organizationalUnit = "IT Department",
            locality = "San Francisco",
            state = "California",
            country = "US"
        )
        
        val result = keyAndCsrManager.generateKeyPairAndCsr(subject)
        assertTrue(result is CertificateResult.Success)
        val (_, csr) = (result as CertificateResult.Success).data
        
        val subjectStr = csr.subject.toString()
        assertTrue(subjectStr.contains("CN=api.example.com"))
        assertTrue(subjectStr.contains("O=Example Corp"))
        assertTrue(subjectStr.contains("OU=IT Department"))
        assertTrue(subjectStr.contains("L=San Francisco"))
        assertTrue(subjectStr.contains("ST=California"))
        assertTrue(subjectStr.contains("C=US"))
    }

    @Test
    fun `Multiple key generations should produce different keys`() {
        val result1 = keyAndCsrManager.generateKeyPair()
        val result2 = keyAndCsrManager.generateKeyPair()
        
        assertTrue(result1 is CertificateResult.Success)
        assertTrue(result2 is CertificateResult.Success)
        
        val keyPair1 = (result1 as CertificateResult.Success).data
        val keyPair2 = (result2 as CertificateResult.Success).data
        
        // Keys should be different
        assertFalse(keyPair1.private.encoded.contentEquals(keyPair2.private.encoded))
        assertFalse(keyPair1.public.encoded.contentEquals(keyPair2.public.encoded))
    }
}