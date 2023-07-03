<?php

namespace App\Libraries;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtLibrary
{
    protected $key;
    private $request;

    /**
     * JwtLibrary constructor.
     */
    public function __construct()
    {
        $this->key = getenv('JWT_SECRET_KEY');
        $this->request = \Config\Services::request();
    }

    /**
     * Generates a JWT token based on the given payload.
     *
     * @param array $payload The payload to include in the token.
     * @return string The generated JWT token.
     */
    public function generateToken(array $payload)
    {
        $payload['exp'] = time() + 3600; // Token valid for 1 hour

        return JWT::encode($payload, $this->key, 'HS256');
    }

    /**
     * Validates a JWT token.
     *
     * @param string $token The JWT token to validate.
     * @return array|false The decoded token payload if valid, false otherwise.
     */
    public function validateToken(string $token)
    {
        try {
            $decoded = JWT::decode($token, new Key($this->key, 'HS256'));
            return (array) $decoded;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Retrieves the value of the Authorization header from the request.
     *
     * @return string|null The Authorization header value, or null if not found.
     */
    protected function getRequestHeader()
    {
        $headers = null;
        
        if ($this->request->getServer('Authorization')) {
            $headers = $this->request->getServer('Authorization');
        } else if ($this->request->getServer('HTTP_AUTHORIZATION')) { // Nginx or fast CGI
            $headers = $this->request->getServer('HTTP_AUTHORIZATION');
        }

        return $headers;
    }

    /**
     * Retrieves the Bearer token from the Authorization header.
     *
     * @return string|null The Bearer token, or null if not found.
     */
    public function getBearerToken()
    {
        $headers = $this->getRequestHeader();

        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }

        return null;
    }
}
