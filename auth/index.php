<?php
// Cargar dependencias
require_once '../config/config.php';
require_once '../config/jwt.php';
require_once '../config/authcookie.php';
require_once '../config/fileManager.php';
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
            'type' => "register",
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

    // Obtener el usuario y su contraseña desde la base de datos
    $stmt = $pdo->prepare("SELECT id, password_hash FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        Flight::jsonHalt(["message" => "El usuario con este email no está registrado."], 400);
    }

    // Verificar la contraseña
    if (!password_verify($password, $user['password_hash'])) {
        Flight::jsonHalt(["message" => "La contraseña es incorrecta."], 401);
    }

    $id = $user['id'];

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
            'type' => "login",
        ];

        $cacheItem->set($cacheData);
        $cacheItem->expiresAfter(7*60);
        $cache->save($cacheItem);
    }

    // Responder con un mensaje de éxito y el token
    Flight::json(["message" => "Usuario registrado temporalmente.", "token" => $token, "expiration" => time() + 420], 200);
});

Flight::route('POST /validate', function(){
    global $pdo;
    $cache = require '../config/cache.php';

    // Obtener los datos de la solicitud
    $jsonData = file_get_contents("php://input");

    // Intentar decodificar el JSON
    $data = json_decode($jsonData, true);  // Decodificar JSON a array asociativo
    if (!isset($data['key'])) Flight::jsonHalt(["message" => "Faltan datos en la solicitud."], 400);
    
    $key = $data["key"];
    $headers = getallheaders();
    $jwt = $headers['Authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'];
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
    
    $userType = $cacheData["type"];

    try {
        $ip = Flight::request()->ip ?? $_SERVER['REMOTE_ADDR'];
        $agent = Flight::request()->user_agent ?? $_SERVER['HTTP_USER_AGENT'];
        $id = $cacheData['id'];
        $inicial = "inicial";
        // Convertir a formato 'YYYY-MM-DD HH:MM:SS'
        $formattedDate = date('Y-m-d H:i:s', $cacheData['timestamp']);
        $lastDate = date('Y-m-d H:i:s', time());

        switch($userType){
            case "register":
                // 1️⃣ **Guardar en `usuarios` (solo si no existe)**
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE id = :id");
                $stmt->bindParam(':id', $userData['id']);
                $stmt->execute();
                $userExists = $stmt->fetchColumn();

                if ($userExists == 0) {
                    $fm = new FileManager();

                    $stmt = $pdo->prepare("INSERT INTO usuarios (id, nombre, apellidos, email, password_hash) VALUES (:id, :username, :lastname, :email, :password_hash)");
                    $stmt->bindParam(':id', $id);
                    $stmt->bindParam(':username', $cacheData['username']);
                    $stmt->bindParam(':lastname', $cacheData['lastname']);
                    $stmt->bindParam(':email', $cacheData['email']);
                    $stmt->bindParam(':password_hash', $cacheData['password']);
                    $stmt->execute();

                    $stmt = $pdo->prepare("INSERT INTO token (token, ultima_fecha, propietario, ip_origen) VALUES (:token, :ultima_fecha, :propietario, :ip_origen)");
                    $stmt->bindParam(':token', $key);
                    $stmt->bindParam(':ultima_fecha', $formattedDate);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->bindParam(':ip_origen', $ip);
                    $stmt->execute();
                
                    $stmt = $pdo->prepare("INSERT INTO historial_pass (password_hash, tipo, propietario) VALUES (:password_hash, :tipo, :propietario)");
                    $stmt->bindParam(':password_hash', $cacheData['password']);
                    $stmt->bindParam(':tipo', $inicial);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute();
                
                    $stmt = $pdo->prepare("INSERT INTO registro_conexiones (ip_origen, navegador, propietario) VALUES (:ip_origen, :navegador, :propietario)");
                    $stmt->bindParam(':ip_origen', $ip);
                    $stmt->bindParam(':navegador', $agent);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute(); 

                    $stmt = $pdo->prepare("INSERT INTO directorios (nombre, propietario) VALUES ('/', :propietario)");
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute(); 

                    $stmt = $pdo->prepare("INSERT INTO almacenamiento (propietario, almacenamiento_maximo, almacenamiento_actual, tamaño_alerta) VALUES (:propietario, 5368709120, 0, 4294967296)");
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute(); 

                    $fm->createDirectory($id);
                }
            
                Flight::json(["message" => "Usuario registrado en la base de datos."], 200); // Responder con datos JSON
                break;
                
            case "login":
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE id = :id");
                $stmt->bindParam(':id', $userData['id']);
                $stmt->execute();
                $userExists = $stmt->fetchColumn();
        
                $stmt = $pdo->prepare("SELECT token FROM token WHERE propietario = :id");
                $stmt->bindParam(':id', $userData['id']);
                $stmt->execute();
                $keyExists = $stmt->fetchColumn();
        
                if ($userExists !== 0 && isset($keyExists) && $keyExists === $key) {  
                    $stmt = $pdo->prepare("UPDATE token SET ultima_fecha = :ultima_fecha WHERE propietario = :propietario");
                    $stmt->bindParam(':ultima_fecha', $lastDate);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute();
            
                    $stmt = $pdo->prepare("INSERT INTO registro_conexiones (ip_origen, navegador, propietario) VALUES (:ip_origen, :navegador, :propietario)");
                    $stmt->bindParam(':ip_origen', $ip);
                    $stmt->bindParam(':navegador', $agent);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute(); 
                    Flight::json(["message" => "Inicio de sesión correcto."], 200); // Responder con datos JSON
                }else{
                    Flight::json(["message" => "Token inválido o usuario no autorizado."], 401);
                }
                break;
            case "pass":
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE id = :id");
                $stmt->bindParam(':id', $userData['id']);
                $stmt->execute();
                $userExists = $stmt->fetchColumn();
        
                $stmt = $pdo->prepare("SELECT token FROM token WHERE propietario = :id");
                $stmt->bindParam(':id', $userData['id']);
                $stmt->execute();
                $keyExists = $stmt->fetchColumn();
        
                if ($userExists !== 0 && isset($keyExists) && $keyExists === $key) {  
                    $stmt = $pdo->prepare("UPDATE token SET ultima_fecha = :ultima_fecha WHERE propietario = :propietario");
                    $stmt->bindParam(':ultima_fecha', $lastDate);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute();
            
                    $stmt = $pdo->prepare("INSERT INTO registro_conexiones (ip_origen, navegador, propietario) VALUES (:ip_origen, :navegador, :propietario)");
                    $stmt->bindParam(':ip_origen', $ip);
                    $stmt->bindParam(':navegador', $agent);
                    $stmt->bindParam(':propietario', $id);
                    $stmt->execute(); 
                    Flight::json(["message" => "Validación token correcto."], 200); // Responder con datos JSON
                }else{
                    Flight::json(["message" => "Token inválido o usuario no autorizado."], 401);
                }
                break;
            default:
                Flight::jsonHalt(["message" => "Tipo de usuario no válido."], 400);
                break;
        }
    } catch (PDOException $e) {
        Flight::json(["message" => "Error con el usuario.", "error" => $e->getMessage()], 400);
    }

    // Eliminar el archivo de la caché
    $cache->deleteItem(md5($jwt));
});

// Ruta para verificar el estado del token
Flight::route('GET /check-register', function() {

    // Desactiva el límite de tiempo, pero se debe usar con precaución
    set_time_limit(0); 
    
    global $pdo;

    // Recuperar el encabezado Authorization
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;
    
    if (!$authHeader) {
        Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    }
    
    $jwt = str_replace('Bearer ', '', $authHeader);
    
    // Decodificar el token JWT
    try {
        $tokenData = JWTHandler::decode($jwt);
    } catch (Exception $e) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    }

    $userID = $tokenData["data"]->id;

    if ($userID === null) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    }
    
    // Establecer el tiempo límite de espera (7 minutos)
    $expirationTime = time() + 420; // 7 minutos en segundos

    // Bucle para verificar si la clave ha sido insertada en la base de datos
    while (time() < $expirationTime) {
        // Consultar la base de datos para ver si la clave está asociada al usuario
        $stmt = $pdo->prepare("SELECT * FROM `token` WHERE `propietario` = :id LIMIT 1");
        $stmt->bindParam(":id", $userID);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            // Si se encuentra la clave, generar la cookie de autenticación
            generateAuthCookie($userID);
            Flight::json(["message" => "Registro completado"], 200);
            return;
        }

        // Esperar 5 segundos antes de volver a consultar
        usleep(5000000);  // 5 segundos
    }

    // Si no se encuentra la clave en el tiempo límite
    Flight::jsonHalt(["message" => "Error: No se insertó la clave en el tiempo límite"], 400);

    // Cerrar la conexión con la base de datos
    $pdo = null;
});

Flight::route('GET /check-login', function() {

    // Desactiva el límite de tiempo, pero se debe usar con precaución
    set_time_limit(0); 
    
    global $pdo;

    // Recuperar el encabezado Authorization
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;
    
    if (!$authHeader) {
        Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    }
    
    $jwt = str_replace('Bearer ', '', $authHeader);
    
    // Decodificar el token JWT
    try {
        $tokenData = JWTHandler::decode($jwt);
    } catch (Exception $e) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    }

    $userID = $tokenData["data"]->id;

    if ($userID === null) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    }
    
    // Establecer el tiempo límite de espera (7 minutos)
    $initTime = time();
    $expirationTime = time() + 420; // 7 minutos en segundos

    // Bucle para verificar si la clave ha sido insertada en la base de datos
    while (time() < $expirationTime) {
        // Consultar la base de datos para ver si la clave está asociada al usuario
        $stmt = $pdo->prepare("SELECT ultima_fecha FROM `token` WHERE `propietario` = :id LIMIT 1");
        $stmt->bindParam(":id", $userID);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result && strtotime($result["ultima_fecha"]) > $initTime) {
            // Si se encuentra la clave, generar la cookie de autenticación
            generateAuthCookie($userID);
            Flight::json(["message" => "Registro completado"], 200);
            return;
        }

        // Esperar 5 segundos antes de volver a consultar
        usleep(5000000);  // 5 segundos
    }

    // Si no se encuentra la clave en el tiempo límite
    Flight::jsonHalt(["message" => "Error: No se insertó la clave en el tiempo límite"], 400);

    // Cerrar la conexión con la base de datos
    $pdo = null;
});

Flight::route('POST /pass', function() {
    global $pdo;
    $cache = require '../config/cache.php';
    // Leer los datos JSON del cuerpo de la solicitud
    $jsonData = file_get_contents("php://input");

    // Intentar decodificar el JSON
    $data = json_decode($jsonData, true);  // Decodificar JSON a array asociativo

    // Verificar si los datos necesarios están presentes
    if (!isset($data["email"])) Flight::jsonHalt(["message" => "Faltan datos para registrar el usuario."], 400);

    // Obtener los valores desde el JSON
    $email = $data["email"];

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
            'timestamp' => time(),
            'type' => "pass",
        ];

        $cacheItem->set($cacheData);
        $cacheItem->expiresAfter(7*60);
        $cache->save($cacheItem);
    }

    // Responder con un mensaje de éxito y el token
    Flight::json(["message" => "Usuario registrado temporalmente.", "token" => $token, "expiration" => time() + 420], 200);
});

Flight::route('POST /change-pass', function () {
    global $pdo;

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    if (!isset($data["email"]) || !isset($data["password"])) {
        Flight::json(["message" => "Faltan datos para cambiar la contraseña."], 400);
        return;
    }

    $email = $data["email"];
    $newPassword = $data["password"];

    $headers = getallheaders();
    if (!array_key_exists('Authorization', $headers)) Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    $jwt = $headers['Authorization'];
    
    // Decodificar token
    $userData = JWTHandler::decode($jwt);
    if ($userData === null) Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);

    if (trim($newPassword) === "") {
        Flight::json(["message" => "La contraseña no puede estar vacía."], 400);
        return;
    }

    // Obtener la contraseña actual del usuario
    $stmt = $pdo->prepare("SELECT id, password_hash FROM usuarios WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        Flight::json(["message" => "El usuario con este email no está registrado."], 404);
        return;
    }

    $id = $user['id'];
    $currentHash = $user['password_hash'];

    // Verificar si la nueva contraseña es igual a la actual
    if (password_verify($newPassword, $currentHash)) {
        Flight::json(["message" => "La nueva contraseña no puede ser igual a la anterior."], 400);
        return;
    }

    // Hashear y actualizar la nueva contraseña
    $newHashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

    $pdo->beginTransaction();

    try {
        // 1. Actualizar contraseña en la tabla usuarios
        $stmt = $pdo->prepare("UPDATE usuarios SET password_hash = :password_hash WHERE email = :email");
        $stmt->bindParam(':password_hash', $newHashedPassword);
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        // 2. Marcar como inactivo cualquier contraseña anterior en historial_pass
        $stmt = $pdo->prepare("UPDATE historial_pass SET estado = 'deshabilitada' WHERE propietario = :propietario AND estado = 'activa'");
        $stmt->bindParam(':propietario', $id);
        $stmt->execute();

        // 3. Insertar nueva contraseña como activa en historial_pass
        $stmt = $pdo->prepare("INSERT INTO historial_pass (password_hash, tipo, propietario) VALUES (:password_hash, 'recuperacion', :propietario)");
        $stmt->bindParam(':password_hash', $newHashedPassword);
        $stmt->bindParam(':propietario', $id);
        $stmt->execute();

        $pdo->commit();

        Flight::json(["message" => "Contraseña actualizada correctamente"], 200);

    } catch (Exception $e) {
        $pdo->rollBack();
        Flight::json(["message" => "Error al actualizar la contraseña", "error" => $e->getMessage()], 500);
    }
});

Flight::route('GET /check-pass', function() {

    // Desactiva el límite de tiempo, pero se debe usar con precaución
    set_time_limit(0); 
    
    global $pdo;

    // Recuperar el encabezado Authorization
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;
    
    if (!$authHeader) {
        Flight::jsonHalt(["message" => "Faltan datos de autorización."], 400);
    }
    
    $jwt = str_replace('Bearer ', '', $authHeader);
    
    // Decodificar el token JWT
    try {
        $tokenData = JWTHandler::decode($jwt);
    } catch (Exception $e) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    }

    $userID = $tokenData["data"]->id;

    if ($userID === null) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 400);
    }
    
    // Establecer el tiempo límite de espera (7 minutos)
    $initTime = time();
    $expirationTime = time() + 420; // 7 minutos en segundos

    // Bucle para verificar si la clave ha sido insertada en la base de datos
    while (time() < $expirationTime) {
        // Consultar la base de datos para ver si la clave está asociada al usuario
        $stmt = $pdo->prepare("SELECT ultima_fecha FROM `token` WHERE `propietario` = :id LIMIT 1");
        $stmt->bindParam(":id", $userID);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result && strtotime($result["ultima_fecha"]) > $initTime) {
            // Si se encuentra la clave, generar la cookie de autenticación
            Flight::json(["message" => "Registro completado"], 200);
            return;
        }

        // Esperar 5 segundos antes de volver a consultar
        usleep(5000000);  // 5 segundos
    }

    // Si no se encuentra la clave en el tiempo límite
    Flight::jsonHalt(["message" => "Error: No se insertó la clave en el tiempo límite"], 400);

    // Cerrar la conexión con la base de datos
    $pdo = null;
});

// Iniciar la aplicación
Flight::start();
?>
