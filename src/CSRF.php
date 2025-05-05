<?php
/**
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

class CSRF {

    protected array $hashes;

    /**
     * Initialize a CSRF instance
     * @param string  $name Session name
     * @param string  $inputName Form name
     * @param integer $hashTime2Live Default seconds hash before expiration
     * @param integer $hashSize      Default hash size in chars
     */
    public function __construct(
        protected string $name = 'csrf-lib',
        protected string $inputName = 'key-awesome',
        protected int $hashTime2Live = 0,
        protected int $hashSize = 64
    ) {
        // Load hash list
        $this->load();
    }

    /**
     * Generate a CSRF_Hash
     * @param  string  $context    Name of the form
     * @param  integer $time2Live  Seconds before expiration
     * @param  integer $max_hashes Clear old context hashes if more than this number
     */
    protected function generateHash(string $context = '', int $time2Live = -1, int $max_hashes = 5): CSRFHash {
        
        // If no time2live (or invalid) use default
        if ($time2Live < 0) {
            $time2Live = $this->hashTime2Live;
        }
        
        // Generate new hash
        $hash = new CSRFHash($context, $time2Live, $this->hashSize);
        // Save it
        $this->hashes[] = $hash;
        if ($this->clearHashes($context, $max_hashes) === 0) {
            $this->save();
        }

        // Return hash info
        return $hash;
    }

    /**
     * Get the hashes of a context
     * @param  string  $context    the group to clean
     * @param  integer $max_hashes max hashes to get
     * @return array               array of hashes as strings
     */
    public function getHashes(string $context = '', int $max_hashes = -1): array {
        
        $len = count($this->hashes);
        $hashes = [];
        // Check in the hash list
        for ($i = $len - 1; $i >= 0 && $len > 0; $i--) {
            
            /** @psalm-suppress MixedMethodCall */
            if ($this->hashes[$i]->inContext($context)) {
                
                /** @psalm-suppress MixedAssignment */
                $hashes[] = $this->hashes[$i]->get();
                $len--;
            }
        }
        
        return $hashes;
    }

    /**
     * Clear the hashes of a context
     * @param  string  $context    the group to clean
     * @param  integer $max_hashes ignore first x hashes
     * @return integer             number of deleted hashes
     */
    public function clearHashes(string $context = '', int $max_hashes = 0): int {
        
        $ignore = $max_hashes;
        $deleted = 0;
        // Check in the hash list
        for ($i = count($this->hashes) - 1; $i >= 0; $i--) {
            
            /** @psalm-suppress MixedMethodCall */
            if ($this->hashes[$i]->inContext($context) && $ignore-- <= 0) {
                array_splice($this->hashes, $i, 1);
                $deleted++;
            }
        }
        
        if ($deleted > 0) {
            $this->save();
        }
        
        return $deleted;
    }

    /**
     * Generate an input html element
     * @param  string  $context   Name of the form
     * @param  integer $time2Live Seconds before expire
     * @param  integer $max_hashes Clear old context hashes if more than this number
     * @return string html input element code as a string
     */
    public function input(string $context = '', int $time2Live = -1, int $max_hashes = 5): string {
        
        // Generate hash
        $hash = $this->generateHash($context, $time2Live, $max_hashes);
        // Generate html input string
        return '<input type="hidden" name="' . htmlspecialchars($this->inputName) . '" id="' . htmlspecialchars($this->inputName) . '" value="' . htmlspecialchars($hash->get()) . '"/>';
    }

    /**
     * Generate a script html element with the hash variable
     * @param  string  $context    Name of the form
     * @param  string  $name       The name for the variable
     * @param  string  $declaration The declaration keyword for the variable. Defaults to 'var'
     * @param  integer $time2Live  Seconds before expire
     * @param  integer $max_hashes Clear old context hashes if more than this number
     * @return string             html script element code as a string
     */
    public function script(
        string $context = '', string $name = '', string $declaration = 'var', int $time2Live = -1, int $max_hashes = 5
    ): string {
        
        // Generate html input string
        return '<script type="text/javascript">' 
               . $this->javascript($context, $name, $declaration, $time2Live, $max_hashes)
               . ';</script>';
    }

    /**
     * Generate a javascript variable with the hash
     * @param  string  $context    Name of the form
     * @param  string  $name       The name for the variable
     * @param  string  $declaration The declaration keyword for the variable. Defaults to 'var'
     * @param  integer $time2Live  Seconds before expire
     * @param  integer $max_hashes Clear old context hashes if more than this number
     * @return string             html script element code as a string
     */
    public function javascript(string $context = '', string $name = '', string $declaration = 'var', int $time2Live = -1, int $max_hashes = 5): string {
        
        // Generate hash
        $hash = $this->generateHash($context, $time2Live, $max_hashes);
        // Variable name
        if ($name === '') {
            $name = $this->inputName;
        }

        $jsonEncodedHashVal = json_encode($hash->get());
        
        // Generate html input string
        return $declaration . ' ' . $name . ' = ' . ( ($jsonEncodedHashVal === false) ? "''" : $jsonEncodedHashVal ) . ';';
    }

    /**
     * Generate a string hash
     * @param  string  $context    Name of the form
     * @param  integer $time2Live  Seconds before expire
     * @param  integer $max_hashes Clear old context hashes if more than this number
     * @return string             hash as a string
     */
    public function string(string $context = '', int $time2Live = -1, int $max_hashes = 5): string {
        
        // Generate hash
        $hash = $this->generateHash($context, $time2Live, $max_hashes);
        // Generate html input string
        return $hash->get();
    }

    /**
     * Validate by context
     * @param  string $context Name of the form
     * @return boolean         Valid or not
     */
    public function validate(string $context = '', bool $hash = null): bool {
        
        // If hash was not given, find hash
        if (is_null($hash)) {
            if (isset($_POST[$this->inputName])) {
                $hash = $_POST[$this->inputName];
            } elseif (isset($_GET[$this->inputName])) {
                $hash = $_GET[$this->inputName];
            } else {
                return false;
            }
        }

        // Check in the hash list
        for ($i = count($this->hashes) - 1; $i >= 0; $i--) {
            
            /** @psalm-suppress MixedMethodCall */
            if ($this->hashes[$i]->verify($hash, $context)) {
                array_splice($this->hashes, $i, 1);
                return true;
            }
        }

        return false;
    }

    /**
     * Load hash list
     */
    protected function load(): static {
        
        $this->hashes = [];
        // If there are hashes on the session
        if (isset($_SESSION[$this->name])) {
            
            // Load session hashes
            /** 
             * @psalm-suppress MixedArgument
             * @psalm-suppress MixedAssignment
             */
            $session_hashes = unserialize($_SESSION[$this->name]);
            // Ignore expired
            /** @psalm-suppress MixedArgument */
            for ($i = count($session_hashes) - 1; $i >= 0; $i--) {
                
                // If an expired found, the rest will be expired
                /** 
                 * @psalm-suppress MixedMethodCall
                 * @psalm-suppress MixedArrayAccess
                 */
                if ($session_hashes[$i]->hasExpire()) {
                    break;
                }

                /** @psalm-suppress MixedArrayAccess */
                array_unshift($this->hashes, $session_hashes[$i]);
            }

            /** @psalm-suppress MixedArgument */
            if (count($this->hashes) !== count($session_hashes)) {
                $this->save();
            }
        }
        
        return $this;
    }

    /**
     * Save hash list
     */
    protected function save(): static {
        
        $_SESSION[$this->name] = serialize($this->hashes);
        
        return $this;
    }
}
