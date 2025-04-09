<?php
// validate.php
require_once '../config/config.php';
require_once '../config/jwt.php';

header('Content-Type: application/json');

// Lógica para eliminar archivos caducados
function cleanupCache() {
    $cacheDir = 'cache/';
    $currentTime = time();
    $expirationTime = 420; // 7 minutos = 420 segundos

    // Obtener todos los archivos en la carpeta de caché
    $files = scandir($cacheDir);

    foreach ($files as $file) {
        // Ignorar directorios y archivos ocultos
        if ($file == '.' || $file == '..') {
            continue;
        }

        $filePath = $cacheDir . $file;
        if (file_exists($filePath)) {
            // Obtener el contenido del archivo para leer el timestamp
            $cacheData = json_decode(file_get_contents($filePath), true);
            if (isset($cacheData['timestamp'])) {
                // Verificar si el archivo ha expirado
                if ($currentTime - $cacheData['timestamp'] > $expirationTime) {
                    // Eliminar el archivo si ha expirado
                    unlink($filePath);
                }
            }
        }
    }
}

// Limpiar caché antes de procesar la solicitud
cleanupCache();

// Obtener el token JWT del encabezado
$headers = apache_request_headers();
if (!isset($headers['Authorization'])) {
    echo json_encode(["message" => "Faltan datos de autorización."]);
    exit();
}

$jwt = $headers['Authorization'];

// Decodificar el JWT
$userData = JWTHandler::decode($jwt);
if ($userData === null) {
    echo json_encode(["message" => "Token inválido o expirado."]);
    exit();
}

// Verificar si el token existe en la caché
$cacheFile = 'cache/' . md5($jwt) . '.json';
if (!file_exists($cacheFile)) {
    echo json_encode(["message" => "El token no está presente en la caché."]);
    exit();
}

// Obtener los datos de la caché
$cacheData = json_decode(file_get_contents($cacheFile), true);

// Verificar que los datos del usuario coinciden con los de la caché
if ($cacheData['username'] !== $userData['username'] || $cacheData['password'] !== $userData['password']) {
    echo json_encode(["message" => "Los datos del usuario no coinciden."]);
    exit();
}

// Eliminar el archivo de la caché (ya no es necesario)
unlink($cacheFile);
echo json_encode(["message" => "Usuario registrado en la base de datos."]);
// Guardar los datos del usuario enviados en la solicitud en la base de datos
try {
    // Obtener los datos de la solicitud
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['username']) || !isset($data['password'])) {
        echo json_encode(["message" => "Faltan datos en la solicitud."]);
        exit();
    }

    // Guardar los datos del usuario en la base de datos
    $stmt = $pdo->prepare("INSERT INTO usuarios (nombre, apellidos, email, password_hash) VALUES (:username, :lastname, :email, :password_hash)");
    $stmt->bindParam(':username', $data['username']);
    $stmt->bindParam(':lastname', $data['lastname']);
    $stmt->bindParam(':email', $data['email']);
    $stmt->bindParam(':password_hash', $data['password']);
    $stmt->execute();

    echo json_encode(["message" => "Usuario registrado en la base de datos."]);
} catch (PDOException $e) {
    echo json_encode(["message" => "Error al guardar el usuario: " . $e->getMessage()]);
}
// curl -X POST "http://localhost/api/auth/validate.php" -H "Authorization: <TOKEN>" -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"testpassword\"}"
?>
