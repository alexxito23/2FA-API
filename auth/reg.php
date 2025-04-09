<?php
// register.php
require_once '../config/config.php';
require_once '../config/jwt.php';

// Obtener los datos JSON de la petición
$data = json_decode(file_get_contents("php://input"));

if (!isset($data->username) || !isset($data->password)) {
    echo json_encode(["message" => "Faltan datos para registrar el usuario."]);
    exit();
}

// Generar un token JWT con los datos del usuario
$token = JWTHandler::encode(['username' => $data->username, 'password' => $data->password]);

// Guardar los datos en un archivo temporal con una duración de 7 minutos
$cacheFile = 'cache/' . md5($token) . '.json';  // El archivo se llama con el hash del token para ser único
file_put_contents($cacheFile, json_encode([
    'username' => $data->username,
    'password' => $data->password,
    'timestamp' => time()
]));

// Devolver el token generado
echo json_encode(["message" => "Usuario registrado temporalmente.", "token" => $token]);

// curl -X POST "http://localhost/api/auth/register.php" -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"testpassword\"}"
?>
