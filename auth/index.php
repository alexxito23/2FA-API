<?php
// Cargar dependencias
require_once '../config/config.php';
require_once '../config/jwt.php';
require_once '../config/authcookie.php';
require '../vendor/autoload.php';

// Definir la ruta para obtener todos los usuarios
Flight::route('POST /register', function() {

    global $pdo;
    $cache = require '../config/cache.php';
    // Leer los datos JSON del cuerpo de la solicitud
    $jsonData = file_get_contents("php://input");

    // Intentar decodificar el JSON
    $data = json_decode($jsonData, true);  // Decodificar JSON a array asociativo

    // Verificar si los datos necesarios están presentes
    if (!isset($data["name"]) || !isset($data["lastname"]) || !isset($data["email"]) || !isset($data["password"])) Flight::jsonHalt(["message" => "Faltan datos para registrar el usuario."], 400);

    // Obtener los valores desde el JSON
    $name = $data["name"];
    $lastname = $data["lastname"];
    $email = $data["email"];
    $password = $data["password"];

    // Verificar si el email ya está registrado
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $userExists = $stmt->fetchColumn();

    if ($userExists > 0) Flight::jsonHalt(["message" => "El usuario con este email ya está registrado."], 400);

    // Crear un ID único para el nuevo usuario
    $id = bin2hex(random_bytes(16));

    // Generar un token JWT para el nuevo usuario
    $token = JWTHandler::encode(['id' => $id]);

    // Guardar caché con los datos del usuario
    $cacheItem = $cache->getItem(md5($token));

    if(!$cacheItem->isHit()){
        $cacheData = [
            'id' => $id,
            'username' => $name,
            'lastname' => $lastname,
            'email' => $email,
            'password' => password_hash($password, PASSWORD_DEFAULT),
            'timestamp' => time(),
        ];

        $cacheItem->set($cacheData);
        $cacheItem->expiresAfter(7*60);
        $cache->save($cacheItem);
    }

    // Responder con un mensaje de éxito y el token
    Flight::json(["message" => "Usuario registrado temporalmente.", "token" => $token, "expiration" => time() + 420], 200);
});

Flight::route('POST /login', function() {
    global $pdo;
    $cache = require '../config/cache.php';
    // Leer los datos JSON del cuerpo de la solicitud
    $jsonData = file_get_contents("php://input");

    // Intentar decodificar el JSON
    $data = json_decode($jsonData, true);  // Decodificar JSON a array asociativo

    // Verificar si los datos necesarios están presentes
    if (!isset($data["email"]) || !isset($data["password"])) Flight::jsonHalt(["message" => "Faltan datos para registrar el usuario."], 400);

    // Obtener los valores desde el JSON
    $email = $data["email"];
    $password = $data["password"];

    // Verificar si el email ya está registrado
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $userExists = $stmt->fetchColumn();

    if ($userExists < 1) Flight::jsonHalt(["message" => "El usuario con este email no está registrado."], 400);

    // Obtener ID único para el nuevo usuario
    $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $id = $stmt->fetchColumn();

    // Generar un token JWT para el nuevo usuario
    $token = JWTHandler::encode(['id' => $id]);

    // Guardar caché con los datos del usuario
    $cacheItem = $cache->getItem(md5($token));

    if(!$cacheItem->isHit()){
        $cacheData = [
            'id' => $id,
            'email' => $email,
            'password' => password_hash($password, PASSWORD_DEFAULT),
            'timestamp' => time(),
        ];

        $cacheItem->set($cacheData);
        $cacheItem->expiresAfter(7*60);
        $cache->save($cacheItem);
    }

    // Responder con un mensaje de éxito y el token
    Flight::json(["message" => "Usuario registrado temporalmente.", "token" => $token, "expiration" => time() + 420], 200);
});

Flight::route('POST /confirm', function(){
    global $pdo;
    $cache = require '../config/cache.php';

    $headers = getallheaders();
    $jwt = $headers['Authorization'];
    if (!isset($jwt)) Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    
    // Decodificar token
    $userData = (array) JWTHandler::decode($jwt)["data"];
    if ($userData === null) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    $cacheItem = $cache->getItem(md5($jwt));
    if (!$cacheItem->isHit()) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    // Obtener los datos del usuario desde la caché
    $cacheData = $cacheItem->get();

    // Verificar que los datos del usuario coinciden con los de la caché
    if ($cacheData['id'] !== $userData['id']){
        $cache->deleteItem(md5($jwt));
        Flight::jsonHalt(["message" => "Los datos del usuario no coinciden."], 400);
    }

    try {
        // Obtener los datos de la solicitud
        $key = Flight::request()->data['key'];
        $ip = Flight::request()->ip;
        if (!isset($key)) Flight::jsonHalt(["message" => "Faltan datos en la solicitud."], 400);

        // Convertir a formato 'YYYY-MM-DD HH:MM:SS'
        $formattedDate = date('Y-m-d H:i:s', $cacheData['timestamp']);

        // Guardar los datos del usuario en la base de datos
        $stmt = $pdo->prepare("INSERT INTO usuarios (id, nombre, apellidos, email, password_hash) VALUES (:id, :username, :lastname, :email, :password_hash)");
        $stmt->bindParam(':id', $cacheData['id']);
        $stmt->bindParam(':username', $cacheData['username']);
        $stmt->bindParam(':lastname', $cacheData['lastname']);
        $stmt->bindParam(':email', $cacheData['email']);
        $stmt->bindParam(':password_hash', $cacheData['password']);
        $stmt->execute();
    
        // Guardar los datos de la key en la base de datos
        $stmt = $pdo->prepare("INSERT INTO token (token, fecha_expiracion, propietario, ip_origen) VALUES (:token, :fecha_expiracion, :propietario, :ip_origen)");
        $stmt->bindParam(':token', $key);
        $stmt->bindParam(':fecha_expiracion', $formattedDate);
        $stmt->bindParam(':propietario', $userData['id']);
        $stmt->bindParam(':ip_origen', $ip);
        $stmt->execute();
    
        Flight::json(["message" => "Usuario registrado en la base de datos."], 200); // Responder con datos JSON
    } catch (PDOException $e) {
        Flight::json(["message" => "Error al registrar el usuario en la base de datos.", "error" => $e->getMessage()], 400);
    }

    // Eliminar el archivo de la caché
    $cache->deleteItem(md5($jwt));
    //Flight::redirect("http://localhost:80/api/auth/cookie.php");
});

Flight::route('POST /validate', function(){
    global $pdo;
    $cache = require '../config/cache.php';

    $headers = getallheaders();
    $jwt = $headers['Authorization'];
    if (!isset($jwt)) Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    
    // Decodificar token
    $userData = (array) JWTHandler::decode($jwt)["data"];
    if ($userData === null) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    $cacheItem = $cache->getItem(md5($jwt));
    if (!$cacheItem->isHit()) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    // Obtener los datos del usuario desde la caché
    $cacheData = $cacheItem->get();

    // Verificar que los datos del usuario coinciden con los de la caché
    if ($cacheData['id'] !== $userData['id']){
        $cache->deleteItem(md5($jwt));
        Flight::jsonHalt(["message" => "Los datos del usuario no coinciden."], 400);
    }

    try {
        // Obtener los datos de la solicitud
        $jsonData = file_get_contents("php://input");

        // Intentar decodificar el JSON
        $data = json_decode($jsonData, true);  // Decodificar JSON a array asociativo
        echo $data["key"];
        $ip = Flight::request()->ip ?? $_SERVER['REMOTE_ADDR'];
        $agent = Flight::request()->user_agent ?? $_SERVER['HTTP_USER_AGENT'];
        if (!isset($data['key'])) Flight::jsonHalt(["message" => "Faltan datos en la solicitud."], 400);

        // Convertir a formato 'YYYY-MM-DD HH:MM:SS'
        $formattedDate = date('Y-m-d H:i:s', $cacheData['timestamp']);

        // 1️⃣ **Guardar en `usuarios` (solo si no existe)**
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE id = :id");
        $stmt->bindParam(':id', $id);
        $stmt->execute();
        $userExists = $stmt->fetchColumn();

        if ($userExists == 0) {
            $stmt = $pdo->prepare("INSERT INTO usuarios (id, nombre, apellidos, email, password_hash) VALUES (:id, :username, :lastname, :email, :password_hash)");
            $stmt->bindParam(':id', $id);
            $stmt->bindParam(':username', $cacheData['username']);
            $stmt->bindParam(':lastname', $cacheData['lastname']);
            $stmt->bindParam(':email', $cacheData['email']);
            $stmt->bindParam(':password_hash', $cacheData['password']);
            $stmt->execute();

            $stmt = $pdo->prepare("INSERT INTO token (token, fecha_expiracion, propietario, ip_origen) VALUES (:token, :fecha_expiracion, :propietario, :ip_origen)");
            $stmt->bindParam(':token', $data['key']);
            $stmt->bindParam(':fecha_expiracion', $formattedDate);
            $stmt->bindParam(':propietario', $userData['id']);
            $stmt->bindParam(':ip_origen', $ip);
            $stmt->execute();
    
/*             $stmt = $pdo->prepare("INSERT INTO historial_pass (password_hash, tipo, propietario) VALUES (:password_hash, :tipo, :propietario)");
            $stmt->bindParam(':password_hash', $cacheData['password']);
            $stmt->bindParam(':tipo', "inicial");
            $stmt->bindParam(':propietario', $id);
            $stmt->execute(); */
    
            $stmt = $pdo->prepare("INSERT INTO registro_conexiones (ip_origen, navegador, propietario) VALUES (:ip_origen, :navegador, :propietario)");
            $stmt->bindParam(':ip_origen', $ip);
            $stmt->bindParam(':navegador', $agent);
            $stmt->bindParam(':propietario', $id);
            $stmt->execute(); 
        }
    
        // Guardar los datos de la key en la base de datos

    
        Flight::json(["message" => "Usuario registrado en la base de datos."], 200); // Responder con datos JSON
    } catch (PDOException $e) {
        Flight::json(["message" => "Error al registrar el usuario en la base de datos.", "error" => $e->getMessage()], 400);
    }

    // Eliminar el archivo de la caché
    $cache->deleteItem(md5($jwt));
});

// Ruta para verificar el estado del token
Flight::route('GET /check-token', function() {

    global $pdo;
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;
    if (!$authHeader) Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    $jwt = str_replace('Bearer ', '', $authHeader);
    
    // Decodificar el token JWT
    $tokenData = JWTHandler::decode($jwt);
    $userID = $tokenData["data"]->id;

    if ($userID === null) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    
    // Bucle para verificar cada segundo si la clave ha sido insertada
    while (time() < $tokenData["exp"]) {
        // Consultar si la clave ha sido insertada para el usuario (basado en el ID de usuario)
        $stmt = $pdo->prepare("SELECT * FROM `token` WHERE `propietario` = :id LIMIT 1");
        // Usar bindParam con PDO
        $stmt->bindParam(":id", $userID);  // Asignar el ID del usuario de tipo entero
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            // Si se encuentra la clave en la base de datos
            generateAuthCookie($userID);
            Flight::json(["message" => "Registro completado"], 200);
            return;
        }

        // Esperar 5 segundos antes de volver a consultar
        usleep(5000000);
    }

    Flight::jsonHalt(["message" => "Error: No se insertó la clave en el tiempo límite"], 400);

    // Cerrar la conexión
    $pdo = null;
});

// Iniciar la aplicación
Flight::start();

/*
Flight::route('POST /validate', function(){
    global $pdo;
    $cache = require '../config/cache.php';

    $headers = getallheaders();
    $jwt = $headers['Authorization'];
    if (!isset($jwt)) Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    
    // Decodificar token
    $userData = (array) JWTHandler::decode($jwt)["data"];
    if ($userData === null) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    $cacheItem = $cache->getItem(md5($jwt));
    if (!$cacheItem->isHit()) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    // Obtener los datos del usuario desde la caché
    $cacheData = $cacheItem->get();

    // Verificar que los datos del usuario coinciden con los de la caché
    if ($cacheData['id'] !== $userData['id']){
        $cache->deleteItem(md5($jwt));
        Flight::jsonHalt(["message" => "Los datos del usuario no coinciden."], 400);
    }

    try {
        // Obtener los datos de la solicitud
        $key = Flight::request()->data['key'];
        $ip = Flight::request()->ip;
        $agent = Flight::request()->user_agent;
        if (!isset($key)) Flight::jsonHalt(["message" => "Faltan datos en la solicitud."], 400);

        // Convertir a formato 'YYYY-MM-DD HH:MM:SS'
        $formattedDate = date('Y-m-d H:i:s', $cacheData['timestamp']);

        // Guardar los datos del usuario en la base de datos
        $stmt = $pdo->prepare("INSERT INTO usuarios (id, nombre, apellidos, email, password_hash) VALUES (:id, :username, :lastname, :email, :password_hash)");
        $stmt->bindParam(':id', $cacheData['id']);
        $stmt->bindParam(':username', $cacheData['username']);
        $stmt->bindParam(':lastname', $cacheData['lastname']);
        $stmt->bindParam(':email', $cacheData['email']);
        $stmt->bindParam(':password_hash', $cacheData['password']);
        $stmt->execute();
    
        // Guardar los datos de la key en la base de datos
        $stmt = $pdo->prepare("INSERT INTO token (token, fecha_expiracion, propietario, ip_origen) VALUES (:token, :fecha_expiracion, :propietario, :ip_origen)");
        $stmt->bindParam(':token', $key);
        $stmt->bindParam(':fecha_expiracion', $formattedDate);
        $stmt->bindParam(':propietario', $userData['id']);
        $stmt->bindParam(':ip_origen', $ip);
        $stmt->execute();

        $stmt = $pdo->prepare("INSERT INTO registro_conexiones (ip_origen, navegador, propietario) VALUES (:id, :ip_origen, :navegador, :propietario)");
        $stmt->bindParam(':ip_origen', $ip);
        $stmt->bindParam(':navegador', $agent);
        $stmt->bindParam(':propietario', $id);
        $stmt->execute();
    
        Flight::json(["message" => "Usuario registrado en la base de datos."], 200); // Responder con datos JSON
    } catch (PDOException $e) {
        Flight::json(["message" => "Error al registrar el usuario en la base de datos.", "error" => $e->getMessage()], 400);
    }

    // Eliminar el archivo de la caché
    $cache->deleteItem(md5($jwt));
});

*/

?>
