<?php
/**
 * 
 * Single PHP library file for protection over Cross-Site Request Forgery
 * Easily generate and manage CSRF tokens in groups.
 *
 * 
 * MIT License
 *
 * Copyright (c) 2023 Grammatopoulos Athanasios-Vasileios
 * Copyright (c) 2025 Rotimi Ade
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Rotexsoft;

class CSRFHash {

    protected string $hash;

    protected int $expire;

    /**
     * @param string  $context   [description]
     * @param integer $time2Live Number of seconds before expiration
     */
    public function __construct(protected string $context, int $time2Live = 0, int $hashSize = 64) {
        
        // Generate hash
        $this->hash = $this->generateHash($hashSize);

        // Set expiration time
        $this->expire = ($time2Live > 0) ? time() + $time2Live : 0;
    }

    /**
     * The hash function to use
     * @param  int $n 	Size in bytes
     * @return string 	The generated hash
     */
    protected function generateHash(int $n): string {
        
        return bin2hex(openssl_random_pseudo_bytes((int)($n / 2)));
    }

    /**
     * Check if hash has expired
     */
    public function hasExpire(): bool {
        
        return $this->expire !== 0 && $this->expire <= time();
    }

    /**
     * Verify hash
     */
    public function verify(string $hash, string $context = ''): bool {
        
        return strcmp($context, $this->context) === 0 && !$this->hasExpire() && hash_equals($hash, $this->hash);
    }

    /**
     * Check Context
     */
    public function inContext(string $context = ''): bool {
        
        return (strcmp($context, $this->context) === 0);
    }

    /**
     * Get hash
     */
    public function get(): string {
        
        return $this->hash;
    }
}
