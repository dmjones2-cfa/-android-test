package com.android.pki.certificate

import org.junit.Test
import org.junit.Assert.*

class SimpleIntegrationTest {

    @Test
    fun `CertificateManager should be instantiable`() {
        val manager = CertificateManager()
        assertNotNull(manager)
    }

    @Test
    fun `All main classes should be instantiable`() {
        val manager = CertificateManager()
        val storage = CertificateStorage()
        val keyManager = KeyAndCsrManager()
        val awsClient = AwsPrivateCaClient()
        
        assertNotNull(manager)
        assertNotNull(storage)
        assertNotNull(keyManager)
        assertNotNull(awsClient)
    }

    @Test
    fun `KeyAndCsrManager should generate keys successfully`() {
        val keyManager = KeyAndCsrManager()
        val result = keyManager.generateKeyPair()
        
        assertTrue(result is CertificateResult.Success)
    }

    @Test
    fun `CertificateStorage should work with basic operations`() {
        val storage = CertificateStorage()
        
        assertFalse(storage.hasCertificate("test"))
        assertNull(storage.getCertificateInfo("test"))
        assertTrue(storage.listAliases().isEmpty())
    }
}