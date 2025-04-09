<?php
require_once '../config/config.php';
require_once '../config/jwt.php';
require_once '../config/cleanupCache.php';
require '../vendor/autoload.php';

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json");

if (!isset(getallheaders()['Authorization'])) {
    header("HTTP/1.1 400 Bad Request");
    echo json_encode(["message" => "Falta el token de autorización"]);
    exit;
}

$authHeader = getallheaders()['Authorization'];
$token = str_replace('Bearer ', '', $authHeader);  // Eliminar el prefijo "Bearer" del token

// Verificar el token
$userData = JWTHandler::decode($token);
if (!isset($userData["data"]->id)) {
    header("HTTP/1.1 403 Forbidden");
    echo json_encode(["message" => "Token inválido o expirado"]);
    exit;
}

// Variables de tiempo
$startTime = 1736268240;  // Hora de inicio
$timeout = 7 * 60;    // 7 minutos en segundos
$keyInserted = false; // Variable para saber si la clave ha sido insertada
// Bucle para verificar cada segundo si la clave ha sido insertada
while (time() < $userData["exp"]) {
    // Consultar si la clave ha sido insertada para el usuario (basado en el ID de usuario)
    $stmt = $pdo->prepare("SELECT * FROM `token` WHERE `propietario` = :id LIMIT 1");
    // Usar bindParam con PDO
    $stmt->bindParam(":id", $userData["data"]->id);  // Asignar el ID del usuario de tipo entero
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($result) {
        // Si se encuentra la clave en la base de datos
        $keyInserted = true;
        break;  // Salir del bucle
    }

    // Esperar 1 segundo antes de volver a consultar
    sleep(1);
}

// Responder con el resultado
if ($keyInserted) {
    // Si la clave ha sido insertada antes de los 7 minutos
    echo json_encode(["message" => "Completado", "status" => "success"]);
} else {
    // Si después de 7 minutos no se encuentra la clave
    echo json_encode(["message" => "Error: No se insertó la clave en el tiempo límite", "status" => "error"]);
}

// Cerrar la conexión
$pdo = null;  // Cerrar la conexión correctamente

?>
