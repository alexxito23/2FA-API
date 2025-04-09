<?php
// Habilitar CORS
header("Access-Control-Allow-Origin: *");  // Permite todos los orígenes. Asegúrate de restringirlo en producción.
header("Content-Type: application/json");  // Asegúrate de que la respuesta sea JSON

// Responder a las solicitudes OPTIONS (preflight request)
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);  // No procesar más, solo enviar los encabezados
}

// Verificar el encabezado Authorization
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    $name = $data["name"]
    // Obtener el encabezado Authorization
    $headers = getallheaders();
    
    if (!isset($headers['Authorization'])) {
        // Si no existe el encabezado Authorization
        header("HTTP/1.1 400 Bad Request");
        echo json_encode(["message" => "Falta el token de autorización."]);
        exit;
    }

    $authHeader = $headers['Authorization'];
    $token = str_replace('Bearer ', '', $authHeader);  // Eliminar "Bearer" si está presente

    // Verificar el token
    if ($token !== 'mi_token_secreto') {  // Aquí puedes poner la lógica de verificación real de tu token (por ejemplo, decodificar JWT)
        header("HTTP/1.1 403 Forbidden");
        echo json_encode(["message" => "Token inválido o expirado."]);
        exit;
    }

    // Simular una espera de 7 minutos (420 segundos)
    sleep(420);  // 7 minutos = 420 segundos

    // Si el token es válido y ha pasado el tiempo de espera, responder con un mensaje de éxito
    header("HTTP/1.1 200 OK");
    echo json_encode(["message" => "Token válido. La solicitud fue procesada correctamente.", "data" => $data]);
    exit;
}

// Si el método no es GET, devolver un error
header("HTTP/1.1 405 Method Not Allowed");
echo json_encode(["message" => "Método no permitido."]);
exit;
?>
