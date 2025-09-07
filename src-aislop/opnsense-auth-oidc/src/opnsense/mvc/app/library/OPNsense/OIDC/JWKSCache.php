<?php

namespace OPNsense\OIDC;

class JWKSCache
{
    private $cacheFile;
    private $ttl;

    public function __construct(string $cacheDir, int $ttl = 3600)
    {
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0750, true);
        }
        $this->cacheFile = rtrim($cacheDir, '/') . '/jwks.json';
        $this->ttl = $ttl;
    }

    public function get(callable $fetcher): array
    {
        if (is_file($this->cacheFile)) {
            $age = time() - filemtime($this->cacheFile);
            if ($age < $this->ttl) {
                $data = json_decode(file_get_contents($this->cacheFile), true);
                if (is_array($data)) {
                    return $data;
                }
            }
        }
        $jwks = $fetcher();
        if (is_array($jwks)) {
            file_put_contents($this->cacheFile, json_encode($jwks));
        }
        return $jwks;
    }
}
