package com.android.pki.certificate.examples

import com.android.pki.certificate.*
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Example usage of the PKI Certificate Management Library
 * 
 * This demonstrates the complete workflow:
 * 1. Configure the certificate manager
 * 2. Request a certificate from AWS Private CA
 * 3. Use the certificate for HTTPS client authentication
 */
class CertificateManagerExample {

    fun demonstrateBasicUsage() {
        runBlocking {
            // 1. Configure retry behavior (optional)
            val retryConfig = RetryConfig(
                maxAttempts = 3,
                initialDelayMs = 1000,
                maxDelayMs = 30000,
                backoffFactor = 2.0
            )

            // 2. Create certificate manager
            val certificateManager = CertificateManager(retryConfig)

            // 3. Define certificate subject
            val subject = CertificateSubject(
                commonName = "api.mycompany.com",
                organization = "My Company Inc",
                organizationalUnit = "IT Security",
                locality = "San Francisco",
                state = "California",
                country = "US"
            )

            // 4. Request certificate from AWS Private CA
            val certificateResult = certificateManager.requestCertificate(
                subject = subject,
                caEndpoint = "https://your-private-ca.amazonaws.com/certificates",
                authToken = "your-jwt-token-here"
            )

            // 5. Handle the result
            when (certificateResult) {
                is CertificateResult.Success -> {
                    val certInfo = certificateResult.data
                    println("✅ Certificate successfully created!")
                    println("   Alias: ${certInfo.alias}")
                    println("   Subject: ${certInfo.subject}")
                    println("   Valid until: ${certInfo.notAfter}")
                    
                    // 6. Use certificate for HTTPS client authentication
                    demonstrateHttpsClientUsage(certificateManager, certInfo.alias)
                }
                is CertificateResult.Error -> {
                    println("❌ Certificate request failed: ${certificateResult.message}")
                    certificateResult.cause?.printStackTrace()
                }
            }
        }
    }

    fun demonstrateHttpsClientUsage(certificateManager: CertificateManager, certificateAlias: String) {
        // Create OkHttp client builder
        val clientBuilder = OkHttpClient.Builder()
        
        // Configure with client certificate
        val configuredBuilder = certificateManager.configureOkHttpClient(certificateAlias, clientBuilder)
        
        if (configuredBuilder != null) {
            // Build the client with certificate authentication
            val client = configuredBuilder.build()
            
            // Create a request to an API that requires client certificates
            val request = Request.Builder()
                .url("https://secure-api.example.com/data")
                .header("Accept", "application/json")
                .build()

            try {
                // Execute the request (client certificate will be used automatically)
                val response = client.newCall(request).execute()
                
                if (response.isSuccessful) {
                    println("✅ API call successful with client certificate!")
                    println("   Response code: ${response.code}")
                    // Process response body as needed
                } else {
                    println("❌ API call failed: ${response.code} ${response.message}")
                }
                
                response.close()
            } catch (e: Exception) {
                println("❌ Network error: ${e.message}")
            }
        } else {
            println("❌ Could not configure HTTPS client - certificate not found or invalid")
        }
    }

    fun demonstrateCertificateManagement() {
        val certificateManager = CertificateManager()

        // List all stored certificates
        val aliases = certificateManager.listCertificates()
        println("📋 Stored certificates: ${aliases.size}")
        
        aliases.forEach { alias ->
            val certInfo = certificateManager.getCertificateInfo(alias)
            if (certInfo != null) {
                println("   • $alias")
                println("     Subject: ${certInfo.subject}")
                println("     Valid: ${certInfo.isValid()}")
                println("     Expires: ${certInfo.notAfter}")
            }
        }

        // Check specific certificate
        val targetAlias = "cert_api_mycompany_com_1234567890"
        if (certificateManager.hasCertificate(targetAlias)) {
            println("✅ Certificate '$targetAlias' is available and valid")
            
            // Get detailed information
            val certInfo = certificateManager.getCertificateInfo(targetAlias)
            certInfo?.let {
                println("   Subject: ${it.subject}")
                println("   Issuer: ${it.issuer}")
                println("   Serial Number: ${it.serialNumber}")
                println("   Valid from: ${it.notBefore}")
                println("   Valid until: ${it.notAfter}")
            }
        } else {
            println("❌ Certificate '$targetAlias' not found or invalid")
        }
    }

    fun demonstrateKeyGeneration() {
        val keyAndCsrManager = KeyAndCsrManager()

        // Generate a key pair
        val keyPairResult = keyAndCsrManager.generateKeyPair()
        
        when (keyPairResult) {
            is CertificateResult.Success -> {
                val keyPair = keyPairResult.data
                println("✅ Key pair generated successfully")
                println("   Algorithm: ${keyPair.private.algorithm}")
                println("   Key size: ${keyPair.private.encoded.size * 8} bits (estimated)")
                
                // Create CSR with the generated key pair
                val subject = CertificateSubject(
                    commonName = "example.com",
                    organization = "Example Organization"
                )
                
                val csrResult = keyAndCsrManager.createCsr(keyPair, subject)
                
                when (csrResult) {
                    is CertificateResult.Success -> {
                        val csr = csrResult.data
                        println("✅ CSR created successfully")
                        println("   Subject: ${csr.subject}")
                        
                        // Encode CSR to PEM format
                        val pemResult = keyAndCsrManager.encodeCsrToPem(csr)
                        when (pemResult) {
                            is CertificateResult.Success -> {
                                val pemCsr = pemResult.data
                                println("✅ CSR encoded to PEM format")
                                println("   PEM CSR length: ${pemCsr.length} characters")
                                // In real usage, you would send this PEM CSR to your CA
                            }
                            is CertificateResult.Error -> {
                                println("❌ Failed to encode CSR: ${pemResult.message}")
                            }
                        }
                    }
                    is CertificateResult.Error -> {
                        println("❌ Failed to create CSR: ${csrResult.message}")
                    }
                }
            }
            is CertificateResult.Error -> {
                println("❌ Failed to generate key pair: ${keyPairResult.message}")
            }
        }
    }
}

/**
 * Main function to run the examples
 */
fun main() {
    val example = CertificateManagerExample()
    
    println("=== PKI Certificate Management Library Examples ===\n")
    
    println("1. Key Generation Example:")
    example.demonstrateKeyGeneration()
    
    println("\n2. Certificate Management Example:")
    example.demonstrateCertificateManagement()
    
    println("\n3. Basic Usage Example (Key Generation Only):")
    example.demonstrateKeyGeneration()
    
    println("\n=== Examples completed ===")
}