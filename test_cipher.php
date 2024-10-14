<?php

require 'XSCCipher.php'; // Include the XSCCipher class file

// Create an instance of XSCCipher
$cipher = new XSCCipher(); // You can also pass keys if needed

// Example plaintext to encrypt
$plaintext = "Hello, World!";

// Encrypt the plaintext
try {
    $encrypted = $cipher->encrypt($plaintext);
    echo "Encrypted: " . json_encode($encrypted) . PHP_EOL;

    // Decrypt the data
    $decrypted = $cipher->decrypt($encrypted);
    echo "Decrypted: " . $decrypted . PHP_EOL;

} catch (Exception $e) {
    // Handle errors during encryption/decryption
    echo "Error: " . $e->getMessage() . PHP_EOL;
}