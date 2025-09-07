<?php

namespace OPNsense\OIDC;

class JWT
{
    public static function decodeSegment(string $segment)
    {
        $remainder = strlen($segment) % 4;
        if ($remainder) {
            $segment .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($segment, '-_', '+/'));
        return json_decode($decoded, true);
    }

    public static function parse(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT format');
        }
        return [
            'header' => self::decodeSegment($parts[0]),
            'payload' => self::decodeSegment($parts[1]),
            'signature_raw' => $parts[2]
        ];
    }

    /** Verify RS256 signature */
    public static function verifyRS256(string $jwt, array $jwk): bool
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return false;
        }
        if (($jwk['kty'] ?? '') !== 'RSA') {
            return false;
        }
        $n = self::b64urlToBigInt($jwk['n']);
        $e = self::b64urlToBigInt($jwk['e']);
        // build public key
        $pubKey = self::buildRsaPubKey($n, $e);
        if (!$pubKey) {
            return false;
        }
        $data = $parts[0] . '.' . $parts[1];
        $sig = self::b64urlDecode($parts[2]);
        return openssl_verify($data, $sig, $pubKey, OPENSSL_ALGO_SHA256) === 1;
    }

    private static function b64urlDecode(string $data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private static function b64urlToBigInt(string $data)
    {
        return self::b64urlDecode($data); // raw bytes (OpenSSL uses DER builder below)
    }

    private static function buildRsaPubKey(string $nBytes, string $eBytes)
    {
        // Construct minimal DER sequence for RSA public key (SubjectPublicKeyInfo)
        $mod = self::asn1EncodeInteger($nBytes);
        $exp = self::asn1EncodeInteger($eBytes);
        $seq = self::asn1Wrap(0x30, $mod . $exp);
        // AlgorithmIdentifier for rsaEncryption OID 1.2.840.113549.1.1.1 with NULL
        $alg = hex2bin('300D06092A864886F70D0101010500');
        $bitString = self::asn1Wrap(0x03, chr(0x00) . $seq);
        $spki = self::asn1Wrap(0x30, $alg . $bitString);
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        return openssl_pkey_get_public($pem);
    }

    private static function asn1EncodeInteger(string $bytes)
    {
        // Ensure positive: prepend 0x00 if high bit set
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }
        return self::asn1Wrap(0x02, $bytes);
    }

    private static function asn1Wrap(int $tag, string $value)
    {
        $len = strlen($value);
        if ($len < 128) {
            $lenEnc = chr($len);
        } else {
            $lenBytes = '';
            $n = $len;
            while ($n > 0) {
                $lenBytes = chr($n & 0xFF) . $lenBytes;
                $n >>= 8;
            }
            $lenEnc = chr(0x80 | strlen($lenBytes)) . $lenBytes;
        }
        return chr($tag) . $lenEnc . $value;
    }
}
