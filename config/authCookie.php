<?php

date_default_timezone_set('Europe/Madrid'); // o tu zona real

require_once 'jwt.php';

function generateAuthCookie($userID, $expiresIn = 3600) {
    // **Crear nuevo JWT**
    $payload = [ "id" => $userID ];
    $jwtCookie = JWTHandler::encode($payload, $expiresIn);

    // **Configurar la cookie JWT**
    setcookie("auth", $jwtCookie, [
        "expires" => time() + $expiresIn,
        "path" => "/",
        "httponly" => true,
        "samesite" => "None",
        "secure" => true, // Solo en HTTPS
        "domain" => ".cloudblock.cloud"
    ]);

    return true; // Solo retorna éxito, sin exponer el token
}

?>
