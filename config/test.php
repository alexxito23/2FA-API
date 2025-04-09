<?php
// Asegúrate de que Composer está cargando las dependencias
require_once '../vendor/autoload.php'; 

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secretKey = "supersecretkey";
$issuedAt = time();
$expirationTime = $issuedAt + 3600;  // Expiración en 1 hora
$payload = [
    'iat' => $issuedAt,
    'exp' => $expirationTime,
    'data' => array(
        'userId' => 1,
        'username' => 'Juan'
    )
];

// Generar el token, pasando el algoritmo 'HS256' como tercer parámetro
$jwt = JWT::encode($payload, $secretKey, 'HS256');

echo "Token generado: " . $jwt . "\n";

$decoded = JWT::decode($jwt, new Key($secretKey, 'HS256'));
print_r($decoded);

?>