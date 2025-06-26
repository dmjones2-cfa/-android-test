package com.android.pki.certificate

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class AwsPrivateCaClientTest {

    companion object {
        init {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private lateinit var mockWebServer: MockWebServer
    private lateinit var client: AwsPrivateCaClient
    private val keyAndCsrManager = KeyAndCsrManager()

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()
        client = AwsPrivateCaClient(RetryConfig(maxAttempts = 2, initialDelayMs = 100))
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `requestCertificate should handle successful response`() = runTest {
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

        // Generate a test CSR
        val subject = CertificateSubject(commonName = "test.example.com")
        val keyPairAndCsrResult = keyAndCsrManager.generateKeyPairAndCsr(subject)
        assertTrue(keyPairAndCsrResult is CertificateResult.Success)
        val (_, csr) = (keyPairAndCsrResult as CertificateResult.Success).data
        
        val csrPemResult = keyAndCsrManager.encodeCsrToPem(csr)
        assertTrue(csrPemResult is CertificateResult.Success)
        val csrPem = (csrPemResult as CertificateResult.Success).data

        // Test the request
        val result = client.requestCertificate(
            csrPem = csrPem,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        assertTrue(result is CertificateResult.Success)
        val certificate = (result as CertificateResult.Success).data
        assertNotNull(certificate)
        
        // Verify the request was made correctly
        val request = mockWebServer.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("Bearer test-token", request.getHeader("Authorization"))
        assertEquals("application/json", request.getHeader("Content-Type"))
    }

    @Test
    fun `requestCertificate should handle 4xx client errors without retry`() = runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(400)
                .setBody("Bad Request")
        )

        val subject = CertificateSubject(commonName = "test.example.com")
        val keyPairAndCsrResult = keyAndCsrManager.generateKeyPairAndCsr(subject)
        assertTrue(keyPairAndCsrResult is CertificateResult.Success)
        val (_, csr) = (keyPairAndCsrResult as CertificateResult.Success).data
        
        val csrPemResult = keyAndCsrManager.encodeCsrToPem(csr)
        assertTrue(csrPemResult is CertificateResult.Success)
        val csrPem = (csrPemResult as CertificateResult.Success).data

        val result = client.requestCertificate(
            csrPem = csrPem,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        assertTrue(result is CertificateResult.Error)
        val error = result as CertificateResult.Error
        assertTrue(error.message.contains("400"))
        
        // Should only have made one request (no retries for 4xx)
        assertEquals(1, mockWebServer.requestCount)
    }

    @Test
    fun `requestCertificate should retry on 5xx server errors`() = runTest {
        // First request returns 500, second returns success
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(500)
                .setBody("Internal Server Error")
        )

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

        val subject = CertificateSubject(commonName = "test.example.com")
        val keyPairAndCsrResult = keyAndCsrManager.generateKeyPairAndCsr(subject)
        assertTrue(keyPairAndCsrResult is CertificateResult.Success)
        val (_, csr) = (keyPairAndCsrResult as CertificateResult.Success).data
        
        val csrPemResult = keyAndCsrManager.encodeCsrToPem(csr)
        assertTrue(csrPemResult is CertificateResult.Success)
        val csrPem = (csrPemResult as CertificateResult.Success).data

        val result = client.requestCertificate(
            csrPem = csrPem,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        assertTrue(result is CertificateResult.Success)
        
        // Should have made 2 requests (one failed, one successful)
        assertEquals(2, mockWebServer.requestCount)
    }

    @Test
    fun `requestCertificate should fail after max retries`() = runTest {
        // All requests return 500
        repeat(3) {
            mockWebServer.enqueue(
                MockResponse()
                    .setResponseCode(500)
                    .setBody("Internal Server Error")
            )
        }

        val subject = CertificateSubject(commonName = "test.example.com")
        val keyPairAndCsrResult = keyAndCsrManager.generateKeyPairAndCsr(subject)
        assertTrue(keyPairAndCsrResult is CertificateResult.Success)
        val (_, csr) = (keyPairAndCsrResult as CertificateResult.Success).data
        
        val csrPemResult = keyAndCsrManager.encodeCsrToPem(csr)
        assertTrue(csrPemResult is CertificateResult.Success)
        val csrPem = (csrPemResult as CertificateResult.Success).data

        val result = client.requestCertificate(
            csrPem = csrPem,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        assertTrue(result is CertificateResult.Error)
        val error = result as CertificateResult.Error
        assertTrue(error.message.contains("All 2 attempts failed"))
        
        // Should have made max attempts
        assertEquals(2, mockWebServer.requestCount)
    }

    @Test
    fun `requestCertificate should handle malformed JSON response`() = runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("invalid json")
                .addHeader("Content-Type", "application/json")
        )

        val subject = CertificateSubject(commonName = "test.example.com")
        val keyPairAndCsrResult = keyAndCsrManager.generateKeyPairAndCsr(subject)
        assertTrue(keyPairAndCsrResult is CertificateResult.Success)
        val (_, csr) = (keyPairAndCsrResult as CertificateResult.Success).data
        
        val csrPemResult = keyAndCsrManager.encodeCsrToPem(csr)
        assertTrue(csrPemResult is CertificateResult.Success)
        val csrPem = (csrPemResult as CertificateResult.Success).data

        val result = client.requestCertificate(
            csrPem = csrPem,
            caEndpoint = mockWebServer.url("/").toString(),
            authToken = "test-token"
        )

        assertTrue(result is CertificateResult.Error)
        val error = result as CertificateResult.Error
        assertTrue(error.message.contains("All 2 attempts failed"))
    }
}