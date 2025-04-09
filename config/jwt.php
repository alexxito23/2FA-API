<?php
// jwt.php
require_once '../vendor/autoload.php';  // Asegúrate de que la ruta es correcta

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

class JWTHandler {
    private static $secretKey = 'supersecretkey';  // Cambia esta clave a algo más seguro
    private static $issuer = 'localhost';          // El emisor del token

    // Codificar (Generar) el JWT
    public static function encode($data) {
        $issuedAt = time();
        $expirationTime = $issuedAt + 420;  // Expiración 7 minutos
        $payload = array(
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'iss' => self::$issuer,
            'data' => $data
        );

        // Aquí pasamos también el algoritmo (por ejemplo, HS256)
        return JWT::encode($payload, self::$secretKey, 'HS256');
    }

    // Decodificar (Validar) el JWT
    public static function decode($jwt) {
        try {
            // No se pasa por referencia el parámetro $headers
            $decoded = JWT::decode($jwt, new Key(self::$secretKey, 'HS256'));
            return (array) $decoded;
        } catch (Exception $e) {
            return null;  // El token es inválido o ha expirado
        }
    }
}
?>
