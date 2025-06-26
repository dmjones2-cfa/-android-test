# PKI Certificate Management Library for Android

A Kotlin library for managing PKI certificates with AWS Private CA integration, designed for Android applications requiring client certificate authentication.

## Features

- **RSA Key Generation**: Generate 2048-bit RSA key pairs securely on device
- **Certificate Signing Request (CSR) Creation**: Create PKCS#10 CSRs with X.500 subject names
- **AWS Private CA Integration**: Authenticate and request certificates from AWS Private Certificate Authority
- **Certificate Storage**: Secure certificate and private key storage (Android Keystore compatible)
- **HTTPS Client Authentication**: Configure OkHttp clients for client certificate authentication
- **Retry Mechanism**: Exponential backoff retry logic for robust network operations
- **Comprehensive Error Handling**: Detailed error reporting and logging

## API Overview

### Main Classes

#### CertificateManager
The primary interface for certificate operations:

```kotlin
val certificateManager = CertificateManager()

// Request a certificate from AWS Private CA
val subject = CertificateSubject(
    commonName = "api.example.com",
    organization = "Example Corp",
    organizationalUnit = "IT Department",
    locality = "San Francisco",
    state = "California",
    country = "US"
)

val result = certificateManager.requestCertificate(
    subject = subject,
    caEndpoint = "https://your-ca-endpoint.amazonaws.com",
    authToken = "your-auth-token"
)

when (result) {
    is CertificateResult.Success -> {
        val certInfo = result.data
        println("Certificate created: ${certInfo.alias}")
    }
    is CertificateResult.Error -> {
        println("Error: ${result.message}")
    }
}
```

#### Certificate Information
```kotlin
// Check if certificate exists and is valid
if (certificateManager.hasCertificate("cert-alias")) {
    val certInfo = certificateManager.getCertificateInfo("cert-alias")
    println("Subject: ${certInfo?.subject}")
    println("Valid until: ${certInfo?.notAfter}")
}
```

#### HTTPS Client Configuration
```kotlin
// Configure OkHttp client for client certificate authentication
val clientBuilder = OkHttpClient.Builder()
val configuredBuilder = certificateManager.configureOkHttpClient("cert-alias", clientBuilder)

if (configuredBuilder != null) {
    val client = configuredBuilder.build()
    // Use client for HTTPS requests requiring client certificates
} else {
    // Certificate not found or invalid
}
```

### Configuration Classes

#### CertificateSubject
Defines the X.500 distinguished name for the certificate:

```kotlin
data class CertificateSubject(
    val commonName: String,              // Required: CN field
    val organization: String? = null,    // Optional: O field
    val organizationalUnit: String? = null, // Optional: OU field
    val locality: String? = null,        // Optional: L field
    val state: String? = null,          // Optional: ST field
    val country: String? = null         // Optional: C field (2-letter code)
)
```

#### RetryConfig
Configure retry behavior for network operations:

```kotlin
val retryConfig = RetryConfig(
    maxAttempts = 5,          // Maximum retry attempts
    initialDelayMs = 1000,    // Initial delay between retries
    maxDelayMs = 60000,       // Maximum delay cap
    backoffFactor = 1.5       // Exponential backoff multiplier
)

val certificateManager = CertificateManager(retryConfig)
```

## Architecture

### Key Components

1. **KeyAndCsrManager**: Handles RSA key generation and CSR creation using BouncyCastle
2. **AwsPrivateCaClient**: Manages HTTP communication with AWS Private CA using OkHttp
3. **CertificateStorage**: Provides secure storage abstraction (Android Keystore integration)
4. **CertificateManager**: Orchestrates the complete certificate lifecycle

### Security Features

- **Secure Key Generation**: Uses `SecureRandom` for cryptographically secure key generation
- **Standard Algorithms**: RSA-2048 with SHA-256 signatures following industry best practices
- **Secure Storage**: Designed for Android Keystore System integration
- **TLS Communication**: All network communication uses HTTPS with proper certificate validation

### Error Handling

The library uses a `CertificateResult<T>` sealed class for consistent error handling:

```kotlin
sealed class CertificateResult<out T> {
    data class Success<out T>(val data: T) : CertificateResult<T>()
    data class Error(val message: String, val cause: Throwable? = null) : CertificateResult<Nothing>()
}
```

### Retry Logic

Implements exponential backoff with configurable parameters:
- Retries server errors (5xx) but not client errors (4xx)
- Configurable maximum attempts, delays, and backoff factors
- Jitter could be added for production deployments to avoid thundering herd

## Dependencies

- **Kotlin Coroutines**: For asynchronous operations
- **OkHttp**: HTTP client for AWS Private CA communication
- **BouncyCastle**: Cryptographic operations and certificate handling
- **SLF4J**: Logging framework
- **JSON**: Response parsing

## Testing

The library includes comprehensive unit tests covering:
- Key generation and CSR creation
- AWS Private CA client with mock server testing
- Certificate storage operations
- Retry mechanism validation
- Complete integration scenarios

Run tests with:
```bash
./gradlew test
```

## Target Environment

- **Target Android API**: Android 13 (API level 33)
- **Minimum SDK**: Android 8.0 (API level 26) for Android Keystore features
- **JDK**: 17
- **Language**: Kotlin

## Production Considerations

1. **Android Keystore Integration**: Replace `CertificateStorage` mock with actual Android Keystore implementation
2. **Certificate Validation**: Add certificate chain validation for production use
3. **Logging**: Configure appropriate log levels for production
4. **Network Security**: Implement certificate pinning for AWS Private CA endpoints
5. **Error Reporting**: Integrate with crash reporting systems
6. **Performance**: Consider certificate caching strategies for frequently accessed certificates

## License

This library is designed for internal use and follows enterprise security standards.