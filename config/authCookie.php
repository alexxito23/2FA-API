<?php

require_once 'jwt.php';

function generateAuthCookie($userID, $expiresIn = 3600) {
    // **Crear nuevo JWT**
    $payload = [
        "id" => $userID,
        "exp" => time() + $expiresIn // Tiempo de expiración dinámico
    ];
    $jwtCookie = JWTHandler::encode($payload);

    // **Configurar la cookie JWT**
    setcookie("auth", $jwtCookie, [
        "expires" => time() + $expiresIn,
        "path" => "/",
        "httponly" => true,
        "samesite" => "Lax",
        "secure" => false // Solo en HTTPS
    ]);

    return true; // Solo retorna éxito, sin exponer el token
}

?>
