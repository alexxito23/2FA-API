<?php
require_once '../config/config.php';
require_once '../config/jwt.php';
require_once '../config/authcookie.php';
require '../vendor/autoload.php';

/* Flight::before('start', function () {
    header('Access-Control-Allow-Origin: http://localhost:3000');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
});
 */

Flight::route('GET /logout', function() {
    // Expirar la cookie "auth"
    setcookie("auth", "", [
        "expires" => time() - 3600,
        "path" => "/",
        "httponly" => true,
        "samesite" => "Lax",
        "secure" => false // true si usas HTTPS
    ]);

    // Puedes redirigir o devolver una respuesta JSON
    Flight::json([
        "success" => true,
        "message" => "Sesión cerrada correctamente."
    ]);
});

Flight::route('GET /info', function () {
    global $pdo;

    // Leer la cookie 'auth_token'
    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    
    // Decodificar el JWT para obtener el ID del usuario
    $decoded = JWTHandler::decode($jwt);

    // Verifica que $decoded no sea null y tenga la estructura esperada
    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if ($userData === null) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    $userID = $userData["id"] ?? null;

    if (!$userID) {
        Flight::jsonHalt(["message" => "No se pudo obtener el ID del usuario desde el token."], 400);
    }

    // Consultar la base de datos por el usuario
    $stmt = $pdo->prepare("SELECT nombre, apellidos, email FROM usuarios WHERE id = :id LIMIT 1");
    $stmt->bindParam(':id', $userID);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        Flight::jsonHalt(["message" => "Usuario no encontrado."], 404);
    }
    // Devolver los datos del usuario
    Flight::json(["usuario" => $user]);
});

Flight::start();
?>