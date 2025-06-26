package com.android.pki.certificate

import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.mockito.kotlin.*
import java.security.Security

class CertificateManagerTest {

    companion object {
        init {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private lateinit var mockWebServer: MockWebServer
    private lateinit var certificateManager: CertificateManager

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()
        certificateManager = CertificateManager(RetryConfig(maxAttempts = 2, initialDelayMs = 100))
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `requestCertificate should complete full flow successfully`() = runTest {
        // Mock successful certificate response
        val mockCertificate = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAKoK/hJjgL6aMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA2dT1r1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3VwIDAQAB
            o1MwUTAdBgNVHQ4EFgQU9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wHwYDVR0jBBgwFoAU
            9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
            AQsFAAOCAQEAqF8jQ4X1mF1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            -----END CERTIFICATE-----
        """.trimIndent()

        val responseJson = """
            {
                "Certificate": "$mockCertificate"
            }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(responseJson)
                .addHeader("Content-Type", "application/json")
        )

        val subject = CertificateSubject(
            commonName = "api.example.com",
            organization = "Test Corp"
        )

        val result = certificateManager.requestCertificate(
            subject = subject,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        assertTrue(result is CertificateResult.Success)
        val certInfo = (result as CertificateResult.Success).data
        
        assertNotNull(certInfo)
        assertTrue(certInfo.alias.contains("api_example_com"))
        assertEquals("CN=api.example.com, O=Test Corp", certInfo.subject)
        assertTrue(certInfo.isValid())

        // Verify certificate is stored and accessible
        assertTrue(certificateManager.hasCertificate(certInfo.alias))
        assertNotNull(certificateManager.getKeyManager(certInfo.alias))
        assertNotNull(certificateManager.getCertificateInfo(certInfo.alias))
    }

    @Test
    fun `hasCertificate should return false for non-existent certificate`() {
        assertFalse(certificateManager.hasCertificate("non-existent"))
    }

    @Test
    fun `getCertificateInfo should return null for non-existent certificate`() {
        assertNull(certificateManager.getCertificateInfo("non-existent"))
    }

    @Test
    fun `getKeyManager should return null for non-existent certificate`() {
        assertNull(certificateManager.getKeyManager("non-existent"))
    }

    @Test
    fun `configureOkHttpClient should return null for non-existent certificate`() {
        val builder = OkHttpClient.Builder()
        val result = certificateManager.configureOkHttpClient("non-existent", builder)
        assertNull(result)
    }

    @Test
    fun `configureOkHttpClient should configure client for existing certificate`() = runTest {
        // Set up certificate first
        val mockCertificate = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAKoK/hJjgL6aMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA2dT1r1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3VwIDAQAB
            o1MwUTAdBgNVHQ4EFgQU9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wHwYDVR0jBBgwFoAU
            9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
            AQsFAAOCAQEAqF8jQ4X1mF1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            -----END CERTIFICATE-----
        """.trimIndent()

        val responseJson = """
            {
                "Certificate": "$mockCertificate"
            }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(responseJson)
                .addHeader("Content-Type", "application/json")
        )

        val subject = CertificateSubject(commonName = "api.example.com")
        val certResult = certificateManager.requestCertificate(
            subject = subject,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )
        
        assertTrue(certResult is CertificateResult.Success)
        val certInfo = (certResult as CertificateResult.Success).data

        // Test configuring OkHttpClient
        val builder = OkHttpClient.Builder()
        val configuredBuilder = certificateManager.configureOkHttpClient(certInfo.alias, builder)
        
        assertNotNull(configuredBuilder)
        assertSame(builder, configuredBuilder) // Should return the same builder instance
        
        // Build client to ensure SSL configuration is valid
        val client = configuredBuilder!!.build()
        assertNotNull(client.sslSocketFactory)
    }

    @Test
    fun `removeCertificate should remove stored certificate`() = runTest {
        // Set up certificate first
        val mockCertificate = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAKoK/hJjgL6aMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA2dT1r1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3VwIDAQAB
            o1MwUTAdBgNVHQ4EFgQU9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wHwYDVR0jBBgwFoAU
            9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
            AQsFAAOCAQEAqF8jQ4X1mF1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            -----END CERTIFICATE-----
        """.trimIndent()

        val responseJson = """
            {
                "Certificate": "$mockCertificate"
            }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(responseJson)
                .addHeader("Content-Type", "application/json")
        )

        val subject = CertificateSubject(commonName = "api.example.com")
        val certResult = certificateManager.requestCertificate(
            subject = subject,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )
        
        assertTrue(certResult is CertificateResult.Success)
        val certInfo = (certResult as CertificateResult.Success).data

        // Verify certificate exists
        assertTrue(certificateManager.hasCertificate(certInfo.alias))

        // Remove certificate
        val removeResult = certificateManager.removeCertificate(certInfo.alias)
        assertTrue(removeResult is CertificateResult.Success)

        // Verify certificate is removed
        assertFalse(certificateManager.hasCertificate(certInfo.alias))
        assertNull(certificateManager.getCertificateInfo(certInfo.alias))
    }

    @Test
    fun `listCertificates should return all stored certificate aliases`() = runTest {
        // Initially empty
        assertTrue(certificateManager.listCertificates().isEmpty())

        // Set up multiple certificates
        val mockCertificate = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAKoK/hJjgL6aMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA2dT1r1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3VwIDAQAB
            o1MwUTAdBgNVHQ4EFgQU9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wHwYDVR0jBBgwFoAU
            9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
            AQsFAAOCAQEAqF8jQ4X1mF1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            -----END CERTIFICATE-----
        """.trimIndent()

        val responseJson = """
            {
                "Certificate": "$mockCertificate"
            }
        """.trimIndent()

        // Mock multiple responses
        repeat(2) {
            mockWebServer.enqueue(
                MockResponse()
                    .setResponseCode(200)
                    .setBody(responseJson)
                    .addHeader("Content-Type", "application/json")
            )
        }

        val subject1 = CertificateSubject(commonName = "api1.example.com")
        val subject2 = CertificateSubject(commonName = "api2.example.com")

        certificateManager.requestCertificate(
            subject = subject1,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        certificateManager.requestCertificate(
            subject = subject2,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        val aliases = certificateManager.listCertificates()
        assertEquals(2, aliases.size)
    }

    @Test
    fun `getAllCertificateInfo should return info for all stored certificates`() = runTest {
        // Initially empty
        assertTrue(certificateManager.getAllCertificateInfo().isEmpty())

        // Set up certificate
        val mockCertificate = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAKoK/hJjgL6aMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA2dT1r1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3VwIDAQAB
            o1MwUTAdBgNVHQ4EFgQU9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wHwYDVR0jBBgwFoAU
            9jOh9LnNj9SQ7TkL7BcJJ7M5uV0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
            AQsFAAOCAQEAqF8jQ4X1mF1F1F2QK3F3V3J3R3F3V3J3R3F3V3J3R3F3V3J3R3F3V
            -----END CERTIFICATE-----
        """.trimIndent()

        val responseJson = """
            {
                "Certificate": "$mockCertificate"
            }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(responseJson)
                .addHeader("Content-Type", "application/json")
        )

        val subject = CertificateSubject(commonName = "api.example.com")
        certificateManager.requestCertificate(
            subject = subject,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        val allCertInfo = certificateManager.getAllCertificateInfo()
        assertEquals(1, allCertInfo.size)
        assertEquals("CN=api.example.com", allCertInfo[0].subject)
    }

    @Test
    fun `requestCertificate should handle AWS CA errors gracefully`() = runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(400)
                .setBody("Invalid CSR")
        )

        val subject = CertificateSubject(commonName = "api.example.com")
        val result = certificateManager.requestCertificate(
            subject = subject,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "invalid-token"
        )

        assertTrue(result is CertificateResult.Error)
        val error = result as CertificateResult.Error
        assertTrue(error.message.contains("Certificate request failed"))
    }
}