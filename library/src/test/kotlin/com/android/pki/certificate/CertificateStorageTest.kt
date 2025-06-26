package com.android.pki.certificate

import org.junit.Test
import org.junit.Assert.*
import org.junit.Before
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.util.*

class CertificateStorageTest {

    companion object {
        init {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private lateinit var storage: CertificateStorage
    private lateinit var mockCertificate: X509Certificate
    private val keyAndCsrManager = KeyAndCsrManager()

    @Before
    fun setUp() {
        storage = CertificateStorage()
        
        // Create a mock certificate for testing
        mockCertificate = createMockCertificate()
    }

    private fun createMockCertificate(): X509Certificate {
        // For testing purposes, we'll create a self-signed certificate
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        
        // This is a simplified mock - in real tests you might want to use a proper cert builder
        return object : X509Certificate() {
            override fun checkValidity() {}
            override fun checkValidity(date: Date?) {}
            override fun getVersion() = 3
            override fun getSerialNumber() = java.math.BigInteger.valueOf(12345)
            override fun getIssuerDN() = javax.security.auth.x500.X500Principal("CN=Test Issuer")
            override fun getSubjectDN() = javax.security.auth.x500.X500Principal("CN=test.example.com")
            override fun getNotBefore() = Date(System.currentTimeMillis() - 86400000) // 1 day ago
            override fun getNotAfter() = Date(System.currentTimeMillis() + 86400000) // 1 day from now
            override fun getTBSCertificate() = byteArrayOf()
            override fun getSignature() = byteArrayOf()
            override fun getSigAlgName() = "SHA256withRSA"
            override fun getSigAlgOID() = "1.2.840.113549.1.1.11"
            override fun getSigAlgParams() = null
            override fun getIssuerUniqueID() = null
            override fun getSubjectUniqueID() = null
            override fun getKeyUsage() = null
            override fun getExtendedKeyUsage() = null
            override fun getBasicConstraints() = -1
            override fun getSubjectAlternativeNames() = null
            override fun getIssuerAlternativeNames() = null
            override fun getEncoded() = byteArrayOf()
            override fun verify(key: java.security.PublicKey?) {}
            override fun verify(key: java.security.PublicKey?, sigProvider: String?) {}
            override fun toString() = "Mock Certificate"
            override fun getPublicKey() = keyPair.public
            override fun hasUnsupportedCriticalExtension() = false
            override fun getCriticalExtensionOIDs() = null
            override fun getNonCriticalExtensionOIDs() = null
            override fun getExtensionValue(oid: String?) = null
            override fun getIssuerX500Principal() = javax.security.auth.x500.X500Principal("CN=Test Issuer")
            override fun getSubjectX500Principal() = javax.security.auth.x500.X500Principal("CN=test.example.com")
        }
    }

    @Test
    fun `storeCertificate should store certificate successfully`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        val result = storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        
        assertTrue(result is CertificateResult.Success)
    }

    @Test
    fun `hasCertificate should return true for stored valid certificate`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        
        assertTrue(storage.hasCertificate("test-alias"))
    }

    @Test
    fun `hasCertificate should return false for non-existent certificate`() {
        assertFalse(storage.hasCertificate("non-existent"))
    }

    @Test
    fun `getCertificateInfo should return correct information`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        
        val info = storage.getCertificateInfo("test-alias")
        
        assertNotNull(info)
        assertEquals("test-alias", info!!.alias)
        assertEquals("CN=test.example.com", info.subject)
        assertEquals("CN=Test Issuer", info.issuer)
        assertEquals("12345", info.serialNumber)
        assertTrue(info.isValid()) // Should be valid based on our mock dates
    }

    @Test
    fun `getCertificateInfo should return null for non-existent certificate`() {
        val info = storage.getCertificateInfo("non-existent")
        assertNull(info)
    }

    @Test
    fun `getKeyManager should return KeyManager for stored certificate`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        
        val keyManager = storage.getKeyManager("test-alias")
        
        assertNotNull(keyManager)
        assertNotNull(keyManager!!.getCertificateChain("test-alias"))
        assertNotNull(keyManager.getPrivateKey("test-alias"))
    }

    @Test
    fun `getKeyManager should return null for non-existent certificate`() {
        val keyManager = storage.getKeyManager("non-existent")
        assertNull(keyManager)
    }

    @Test
    fun `getCertificate should return stored certificate`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        
        val retrieved = storage.getCertificate("test-alias")
        
        assertNotNull(retrieved)
        assertEquals(mockCertificate, retrieved)
    }

    @Test
    fun `getPrivateKey should return stored private key`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        
        val retrieved = storage.getPrivateKey("test-alias")
        
        assertNotNull(retrieved)
        assertEquals(keyPair.private, retrieved)
    }

    @Test
    fun `removeCertificate should remove stored certificate`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("test-alias", mockCertificate, keyPair.private)
        assertTrue(storage.hasCertificate("test-alias"))
        
        val result = storage.removeCertificate("test-alias")
        
        assertTrue(result is CertificateResult.Success)
        assertFalse(storage.hasCertificate("test-alias"))
    }

    @Test
    fun `listAliases should return all stored aliases`() {
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult is CertificateResult.Success)
        val keyPair = (keyPairResult as CertificateResult.Success).data
        
        storage.storeCertificate("alias1", mockCertificate, keyPair.private)
        storage.storeCertificate("alias2", mockCertificate, keyPair.private)
        storage.storeCertificate("alias3", mockCertificate, keyPair.private)
        
        val aliases = storage.listAliases()
        
        assertEquals(3, aliases.size)
        assertTrue(aliases.contains("alias1"))
        assertTrue(aliases.contains("alias2"))
        assertTrue(aliases.contains("alias3"))
    }

    @Test
    fun `listAliases should return empty list when no certificates stored`() {
        val aliases = storage.listAliases()
        assertTrue(aliases.isEmpty())
    }

    @Test
    fun `multiple certificates can be stored with different aliases`() {
        val keyPairResult1 = keyAndCsrManager.generateKeyPair()
        val keyPairResult2 = keyAndCsrManager.generateKeyPair()
        assertTrue(keyPairResult1 is CertificateResult.Success)
        assertTrue(keyPairResult2 is CertificateResult.Success)
        val keyPair1 = (keyPairResult1 as CertificateResult.Success).data
        val keyPair2 = (keyPairResult2 as CertificateResult.Success).data
        
        storage.storeCertificate("cert1", mockCertificate, keyPair1.private)
        storage.storeCertificate("cert2", mockCertificate, keyPair2.private)
        
        assertTrue(storage.hasCertificate("cert1"))
        assertTrue(storage.hasCertificate("cert2"))
        
        val key1 = storage.getPrivateKey("cert1")
        val key2 = storage.getPrivateKey("cert2")
        
        assertNotNull(key1)
        assertNotNull(key2)
        assertNotEquals(key1, key2) // Different keys
    }
}