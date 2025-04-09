<?php
// auth.php 
header("Content-Type: application/json");
require_once 'usuario.php';

$usuario = new Usuario($pdo);

$request_method = $_SERVER['REQUEST_METHOD'];
$request_uri = explode('/', $_SERVER['REQUEST_URI']);
$action = isset($request_uri[2]) ? $request_uri[2] : '';

// Ruta de registro de usuario (POST /auth/register)
if ($action == 'register' && $request_method == 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $nombre = $input['nombre'];
    $email = $input['email'];
    $password = $input['password'];

    // Registrar al usuario y generar el token
    $token = $usuario->registrar($nombre, $email, $password);

    if ($token) {
        echo json_encode(["token" => $token]);  // Retorna el token JWT
    } else {
        echo json_encode(["message" => "Error al registrar usuario"]);
    }
}

// Ruta para validar el token (POST /auth/validate)
if ($action == 'validate' && $request_method == 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $token = $input['token'];

    // Validar el token JWT
    $decoded = $usuario->validarToken($token);

    if ($decoded) {
        // El token es válido, puedes almacenar más datos si es necesario
        echo json_encode(["message" => "Token válido", "user" => $decoded]);
    } else {
        echo json_encode(["message" => "Token inválido o expirado"]);
    }
}
?>
