<?php

require_once '../config/jwt.php';
require '../vendor/autoload.php';

Flight::route('POST /renew-session', function() {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;
    if (!$authHeader) Flight::jsonHalt(["message" => "No autorizado"], 401);

    $jwt = str_replace('Bearer ', '', $authHeader);
    $tokenData = JWTHandler::decode($jwt);
    $userID = $tokenData["data"]->id;

    if (!$userID) Flight::jsonHalt(["message" => "Token inválido o expirado"], 401);

    // **Regenerar la cookie**
    generateAuthCookie($userID);

    Flight::json(["message" => "Sesión renovada"], 200);
});

Flight::start();
?>