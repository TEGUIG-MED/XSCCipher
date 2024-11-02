<?php

/**
 * XSCCipher Class
 * 
 * This class provides encryption and decryption methods using the 
 * AES-128-GCM algorithm with HMAC for integrity checking.
 * 
 * Developed by TEGUIG-MED
 * 
 * Security Note:
 * This implementation uses AES-128-GCM with HMAC for authentication, 
 * which is considered secure for most applications. For highly sensitive 
 * data, consider using AES-256.
 * 
 */

class XSCCipher
{
    private string $cipherAlgo; // Cipher algorithm
    private string $hmacAlgo; // HMAC algorithm
    private string $encryptionKey; // Encryption key
    private string $hmacKey; // HMAC key
    private int $tagLength; // Tag length for GCM

    /**
     * Constructor for XSCCipher.
     * 
     * @param string|null $encryptionKey Optional encryption key. If not provided, a new key will be generated.
     * @param string|null $hmacKey Optional HMAC key. If not provided, a new key will be generated.
     * @param string $cipherAlgo Optional cipher algorithm (default: 'aes-128-gcm').
     * @param string $hmacAlgo Optional HMAC algorithm (default: 'sha256').
     * @param int $keySize Optional key size in bytes (default: 16).
     * @throws Exception If the provided cipher algorithm is unsupported.
     */
    public function __construct(
        ?string $encryptionKey = null,
        ?string $hmacKey = null,
        string $cipherAlgo = 'aes-128-gcm',
        string $hmacAlgo = 'sha256',
        int $keySize = 16
    ) {
        // Validate algorithm support
        if (!in_array($cipherAlgo, openssl_get_cipher_methods(), true)) {
            throw new Exception("Unsupported cipher algorithm: $cipherAlgo");
        }
        $this->cipherAlgo = $cipherAlgo;

        // Validate HMAC algorithm
        $this->validateHmacAlgorithm($hmacAlgo);
        $this->hmacAlgo = $hmacAlgo;

        // Set tag length for GCM mode
        $this->tagLength = 16; // Standard tag length

        // Generate new keys if not provided
        $this->encryptionKey = $encryptionKey ?? $this->generateKey($keySize);
        $this->hmacKey = $hmacKey ?? $this->generateKey($keySize);
    }

    /**
     * Validate HMAC algorithm.
     *
     * @param string $algorithm The HMAC algorithm to validate.
     * @throws Exception If the algorithm is unsupported.
     */
    private function validateHmacAlgorithm(string $algorithm): void
    {
        $supportedAlgorithms = hash_hmac_algos(); // PHP 7.1+
        if (!in_array($algorithm, $supportedAlgorithms, true)) {
            throw new Exception("Unsupported HMAC algorithm: $algorithm");
        }
    }

    /**
     * Generate a random key of specified size.
     * 
     * @param int $size Key size in bytes.
     * @return string Binary representation of the key.
     * @throws Exception If the size is invalid.
     */
    private function generateKey(int $size): string
    {
        if (!in_array($size, [16, 24, 32])) {
            throw new Exception("Invalid key size. Allowed sizes: 16, 24, or 32 bytes.");
        }
        return random_bytes($size); // Generate a secure random key
    }

    /**
     * Encrypts the provided plaintext using the specified cipher algorithm.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @return array An associative array containing the IV, HMAC, and the encrypted data.
     * @throws Exception If the input is invalid or encryption fails.
     */
    public function encrypt(string $plaintext): array
    {
        $this->validateInput($plaintext);

        $iv = random_bytes(openssl_cipher_iv_length($this->cipherAlgo)); // Generate a random IV
        $encryptedData = openssl_encrypt($plaintext, $this->cipherAlgo, $this->encryptionKey, OPENSSL_RAW_DATA, $iv, $tag);
        
        // Calculate HMAC
        $hmac = hash_hmac($this->hmacAlgo, $encryptedData, $this->hmacKey, true);

        // Return the IV, HMAC, and encrypted data
        return [
            'iv' => bin2hex($iv),
            'hmac' => bin2hex($hmac),
            'data' => bin2hex($encryptedData),
            'tag' => bin2hex($tag),
        ];
    }

    /**
     * Decrypts the provided data using the specified cipher algorithm.
     *
     * @param array $data An associative array containing the IV, HMAC, and encrypted data.
     * @return string The decrypted plaintext.
     * @throws Exception If the input is invalid or HMAC verification fails.
     */
    public function decrypt(array $data): string
    {
        // Validate data input
        if (!isset($data['iv'], $data['hmac'], $data['data'], $data['tag'])) {
            throw new Exception("Invalid input data.");
        }

        // Convert hex data back to binary
        $iv = hex2bin($data['iv']);
        $hmac = hex2bin($data['hmac']);
        $encryptedData = hex2bin($data['data']);
        $tag = hex2bin($data['tag']);

        // Verify HMAC
        $expectedHmac = hash_hmac($this->hmacAlgo, $encryptedData, $this->hmacKey, true);
        if (!hash_equals($expectedHmac, $hmac)) {
            throw new Exception("HMAC verification failed.");
        }

        // Decrypt the data
        $plaintext = openssl_decrypt($encryptedData, $this->cipherAlgo, $this->encryptionKey, OPENSSL_RAW_DATA, $iv, $tag);

        if ($plaintext === false) {
            throw new Exception("Decryption failed.");
        }

        return $plaintext; // Return the decrypted plaintext
    }

    /**
     * Validate input for encryption and decryption.
     *
     * @param string $input The input data to validate.
     * @throws Exception If the input is invalid.
     */
    private function validateInput(string $input): void
    {
        if (empty($input)) {
            throw new Exception("Input cannot be empty.");
        }
    }

    /**
     * Set a new encryption key.
     *
     * @param string $key The new encryption key.
     * @throws Exception If the key length is invalid.
     */
    public function setEncryptionKey(string $key): void
    {
        if (strlen($key) < 16 || strlen($key) > 32) {
            throw new Exception("Invalid key length. Key must be between 16 and 32 bytes.");
        }
        $this->encryptionKey = $key;
    }

    /**
     * Set a new HMAC key.
     *
     * @param string $key The new HMAC key.
     * @throws Exception If the key length is invalid.
     */
    public function setHmacKey(string $key): void
    {
        if (strlen($key) < 16 || strlen($key) > 32) {
            throw new Exception("Invalid HMAC key length. Key must be between 16 and 32 bytes.");
        }
        $this->hmacKey = $key;
    }
}
