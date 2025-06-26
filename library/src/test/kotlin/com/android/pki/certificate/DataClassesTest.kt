package com.android.pki.certificate

import org.junit.Test
import org.junit.Assert.*
import java.util.*

class DataClassesTest {

    @Test
    fun `CertificateSubject toX500Name should format correctly with all fields`() {
        val subject = CertificateSubject(
            commonName = "test.example.com",
            organization = "Test Org",
            organizationalUnit = "Test Unit",
            locality = "Test City",
            state = "Test State",
            country = "US"
        )
        
        val x500Name = subject.toX500Name()
        
        assertEquals("CN=test.example.com, O=Test Org, OU=Test Unit, L=Test City, ST=Test State, C=US", x500Name)
    }

    @Test
    fun `CertificateSubject toX500Name should format correctly with minimal fields`() {
        val subject = CertificateSubject(commonName = "test.example.com")
        
        val x500Name = subject.toX500Name()
        
        assertEquals("CN=test.example.com", x500Name)
    }

    @Test
    fun `CertificateInfo isValid should return true for valid certificate`() {
        val now = Date()
        val notBefore = Date(now.time - 86400000) // 1 day ago
        val notAfter = Date(now.time + 86400000) // 1 day from now
        
        val certInfo = CertificateInfo(
            alias = "test",
            subject = "CN=test",
            issuer = "CN=issuer",
            notBefore = notBefore,
            notAfter = notAfter,
            serialNumber = "123"
        )
        
        assertTrue(certInfo.isValid())
    }

    @Test
    fun `CertificateInfo isValid should return false for expired certificate`() {
        val now = Date()
        val notBefore = Date(now.time - 172800000) // 2 days ago
        val notAfter = Date(now.time - 86400000) // 1 day ago (expired)
        
        val certInfo = CertificateInfo(
            alias = "test",
            subject = "CN=test",
            issuer = "CN=issuer",
            notBefore = notBefore,
            notAfter = notAfter,
            serialNumber = "123"
        )
        
        assertFalse(certInfo.isValid())
    }

    @Test
    fun `RetryConfig should calculate correct delays`() {
        val config = RetryConfig(
            maxAttempts = 3,
            initialDelayMs = 1000,
            maxDelayMs = 10000,
            backoffFactor = 2.0
        )
        
        assertEquals(1000, config.calculateDelay(0))
        assertEquals(2000, config.calculateDelay(1))
        assertEquals(4000, config.calculateDelay(2))
    }

    @Test
    fun `RetryConfig should cap delay at maxDelayMs`() {
        val config = RetryConfig(
            maxAttempts = 10,
            initialDelayMs = 1000,
            maxDelayMs = 5000,
            backoffFactor = 2.0
        )
        
        assertEquals(4000, config.calculateDelay(2))
        assertEquals(5000, config.calculateDelay(3)) // Should be capped at maxDelayMs
        assertEquals(5000, config.calculateDelay(4)) // Should be capped at maxDelayMs
    }

    @Test
    fun `RetryConfig should validate parameters`() {
        assertThrows(IllegalArgumentException::class.java) {
            RetryConfig(maxAttempts = 0)
        }
        
        assertThrows(IllegalArgumentException::class.java) {
            RetryConfig(initialDelayMs = 0)
        }
        
        assertThrows(IllegalArgumentException::class.java) {
            RetryConfig(initialDelayMs = 1000, maxDelayMs = 500)
        }
        
        assertThrows(IllegalArgumentException::class.java) {
            RetryConfig(backoffFactor = 1.0)
        }
    }

    @Test
    fun `CertificateResult Success should map correctly`() {
        val result = CertificateResult.Success(42)
        val mapped = result.map { it * 2 }
        
        assertTrue(mapped is CertificateResult.Success)
        assertEquals(84, (mapped as CertificateResult.Success).data)
    }

    @Test
    fun `CertificateResult Error should not map`() {
        val result = CertificateResult.Error("test error")
        val mapped = result.map { "should not be called" }
        
        assertTrue(mapped is CertificateResult.Error)
        assertEquals("test error", (mapped as CertificateResult.Error).message)
    }

    @Test
    fun `CertificateResult Success should call onSuccess`() {
        val result = CertificateResult.Success(42)
        var called = false
        
        result.onSuccess { called = true }
        
        assertTrue(called)
    }

    @Test
    fun `CertificateResult Error should call onError`() {
        val result = CertificateResult.Error("test error")
        var called = false
        
        result.onError { _, _ -> called = true }
        
        assertTrue(called)
    }
}