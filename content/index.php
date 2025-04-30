<?php
require_once '../config/config.php';
require_once '../config/jwt.php';
require_once '../config/authcookie.php';
require_once '../config/fileManager.php';
require '../vendor/autoload.php';

Flight::route('POST /scan-dir', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if ($userData === null || !isset($userData["id"])) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    
    $userID = $userData["id"];

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    if (!isset($data["directorio"])) {
        Flight::jsonHalt(["message" => "El nombre del directorio es requerido."], 400);
    }

    $directorio = trim($data["directorio"], "/");

    $userDir = $userID . "/" . $directorio;
    $fm = new FileManager();

    $contents = $fm->scanDirectory($userDir);

    if (!$contents) {
        Flight::jsonHalt(["message" => "Directorio no encontrado"], 400);
    }

    // ✅ Paso 1: Buscar o crear raíz "/"
    $stmtRaiz = $pdo->prepare("SELECT id FROM directorios WHERE nombre = '/' AND propietario = ? AND ruta_padre IS NULL LIMIT 1");
    $stmtRaiz->execute([$userID]);
    $padreID = $stmtRaiz->fetchColumn();

    if (!$padreID) {
        Flight::jsonHalt(["message" => "No se encontro la ruta padre"], 400);
    }

    // ✅ Paso 2: Recorrer cada parte del path desde la raíz
    $partes = explode('/', $directorio);
    foreach ($partes as $parte) {
        if($parte !== ""){
            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario AND ruta_padre = :ruta_padre LIMIT 1");
            $stmt->execute([
                ':nombre' => $parte,
                ':propietario' => $userID,
                ':ruta_padre' => $padreID
            ]);
            $idEncontrado = $stmt->fetchColumn();

            if ($idEncontrado) {
                $padreID = $idEncontrado;
            } else {
                $stmtInsert = $pdo->prepare("INSERT INTO directorios (nombre, propietario, ruta_padre) VALUES (?, ?, ?)");
                $stmtInsert->execute([$parte, $userID, $padreID]);
                $padreID = $pdo->lastInsertId();
            }
        }
    }

    // ✅ Paso 3: Insertar archivos y subdirectorios dentro de ese directorio
    foreach ($contents["contenido"] as $item) {
        $nombre = $item["nombre"];
        $tipo = strtolower($item["tipo"]);
        $modificacion = $item["modificacion"];
        $tamano = $item["tamano"] ?? 0;

        if ($tipo === "directorio") {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM directorios WHERE nombre = ? AND propietario = ? AND ruta_padre = ?");
            $stmt->execute([$nombre, $userID, $padreID]);
            $existe = $stmt->fetchColumn();

            if ($existe == 0) {
                $insert = $pdo->prepare("INSERT INTO directorios (nombre, propietario, ruta_padre) VALUES (?, ?, ?)");
                $insert->execute([$nombre, $userID, $padreID]);
            }

        } elseif ($tipo === "archivo") {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM archivos WHERE nombre = ? AND propietario = ? AND ruta = ?");
            $stmt->execute([$nombre, $userID, $padreID]);
            $existe = $stmt->fetchColumn();

            if ($existe == 0) {
                $insert = $pdo->prepare("INSERT INTO archivos (nombre, propietario, ruta, tamaño, fecha) VALUES (?, ?, ?, ?, ?)");
                $insert->execute([$nombre, $userID, $padreID, $tamano, $modificacion]);
            }
        }
    }

    Flight::json($contents, 200);
});

Flight::route('POST /create-dir', function () {
    global $pdo;

    // 1. Validar cookie JWT
    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if ($userData === null || !isset($userData["id"])) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    
    $userID = $userData["id"];

    // 2. Leer JSON del body
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $nombre = $data["nombre"] ?? null;
    $directorio = $data["directorio"] ?? null;

    if (!$nombre || $directorio === null) {
        Flight::jsonHalt(["message" => "Faltan parámetros requeridos."], 400);
    }

    // Limpiar nombre para evitar inyecciones o rutas peligrosas
    $nombreLimpio = basename(trim($nombre));
    $directorio = trim($directorio, "/"); // eliminar barras al principio/final

    // 3. Construir ruta física
    $rutaFisica = $directorio ? "$userID/$directorio/$nombreLimpio" : "$userID/$nombreLimpio";

    // 4. Crear directorio en disco
    $fm = new FileManager();
    if (!$fm->createDirectory($rutaFisica)) {
        Flight::jsonHalt(["message" => "El directorio ya existe o no se pudo crear."], 409);
    }

    // 5. Registrar en la base de datos
    try {
        if ($directorio === "") {
            // Directorio raíz (sin padre)
            $stmt = $pdo->prepare("INSERT INTO directorios (nombre, propietario) VALUES (:nombre, :propietario)");
            $stmt->execute([
                ':nombre' => $nombreLimpio,
                ':propietario' => $userID,
            ]);
        } else {
            // Directorio anidado, buscar el ID del padre
            $rutaPadre = basename($directorio);

            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario LIMIT 1");
            $stmt->execute([
                ':nombre' => $rutaPadre,
                ':propietario' => $userID,
            ]);

            $rutaPadreId = $stmt->fetchColumn();

            if (!$rutaPadreId) {
                Flight::jsonHalt(["message" => "No se encontró el directorio padre."], 404);
            }

            $stmt = $pdo->prepare("INSERT INTO directorios (nombre, propietario, ruta_padre) VALUES (:nombre, :propietario, :ruta_padre)");
            $stmt->execute([
                ':nombre' => $nombreLimpio,
                ':propietario' => $userID,
                ':ruta_padre' => $rutaPadreId,
            ]);
        }

        Flight::json(["message" => "Directorio creado con éxito."], 201);
    } catch (PDOException $e) {
        Flight::jsonHalt(["message" => "Error de base de datos: " . $e->getMessage()], 500);
    }
});

Flight::route('POST /delete-dir', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userID = $userData["id"];
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $nombre = $data["nombre"] ?? null;
    $directorio = $data["directorio"] ?? null;

    if (!$nombre || $directorio === null) {
        Flight::jsonHalt(["message" => "Faltan parámetros requeridos."], 400);
    }

    $nombreLimpio = basename(trim($nombre));
    $directorio = trim($directorio, "/");

    try {
        $nombrePadre = !empty($directorio) ? basename($directorio) : '/';
        $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario");
        $stmt->execute([
            ':nombre' => $nombrePadre,
            ':propietario' => $userID
        ]);
        $idPadre = $stmt->fetchColumn();

        if (!$idPadre) {
            Flight::jsonHalt(["message" => "No se encontró el directorio padre."], 404);
        }

        $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario AND ruta_padre = :ruta_padre LIMIT 1");
        $stmt->execute([
            ':nombre' => $nombreLimpio,
            ':propietario' => $userID,
            ':ruta_padre' => $idPadre
        ]);
        $directorioId = $stmt->fetchColumn();

        if (!$directorioId) {
            Flight::jsonHalt(["message" => "Directorio no encontrado."], 404);
        }

        $rutaRelativa = $userID . '/' . ($directorio ? "$directorio/$nombreLimpio" : $nombreLimpio);
        $fm = new FileManager();
        $fm->deleteDirectory($rutaRelativa);

        $totalEliminado = eliminarDirectorioRecursivo($directorioId, $pdo);

        $stmtUpdate = $pdo->prepare("UPDATE almacenamiento SET almacenamiento_actual = GREATEST(almacenamiento_actual - ?, 0) WHERE propietario = ?");
        $stmtUpdate->execute([$totalEliminado, $userID]);

        Flight::json(["message" => "Directorio y contenido eliminados correctamente."], 200);

    } catch (PDOException $e) {
        Flight::jsonHalt(["message" => "Error al eliminar: " . $e->getMessage()], 500);
    }
});

function eliminarDirectorioRecursivo(int $directorioId, PDO $pdo): int {
    $totalEliminado = 0;

    $stmt = $pdo->prepare("SELECT id FROM directorios WHERE ruta_padre = :id");
    $stmt->execute([':id' => $directorioId]);
    $subdirectorios = $stmt->fetchAll(PDO::FETCH_COLUMN);

    foreach ($subdirectorios as $subId) {
        $totalEliminado += eliminarDirectorioRecursivo($subId, $pdo);
    }

    $stmt = $pdo->prepare("SELECT id, nombre, tamaño FROM archivos WHERE ruta = :id");
    $stmt->execute([':id' => $directorioId]);
    $archivos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($archivos as $archivo) {
        $archivoId = $archivo['id'];
        $nombreArchivo = $archivo['nombre'];
        $totalEliminado += (int)$archivo['tamaño'];

        notificarEliminacionCompartidos($pdo, $archivoId, 'archivo', $nombreArchivo);
        eliminarComparticionesYNotificaciones($pdo, $archivoId, 'archivo');
    }

    $stmt = $pdo->prepare("DELETE FROM archivos WHERE ruta = :id");
    $stmt->execute([':id' => $directorioId]);

    notificarEliminacionCompartidos($pdo, $directorioId, 'directorio', obtenerNombreElemento($pdo, 'directorio', $directorioId));
    eliminarComparticionesYNotificaciones($pdo, $directorioId, 'directorio');

    $stmt = $pdo->prepare("DELETE FROM directorios WHERE id = :id");
    $stmt->execute([':id' => $directorioId]);

    return $totalEliminado;
}

Flight::route('POST /delete-file', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if ($userData === null || !isset($userData["id"])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userID = $userData["id"];
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['nombre'], $data['directorio'])) {
        Flight::json(['error' => 'Faltan parámetros'], 400);
        return;
    }

    $nombre = $data['nombre'];
    $directorio = $data['directorio'];
    $nombreLimpio = basename(trim($nombre));
    $directorio = trim($directorio, "/");
    $rutaFisica = $directorio ? "$userID/$directorio/$nombreLimpio" : "$userID/$nombreLimpio";

    $fm = new FileManager();
    $resultado = $fm->eliminarFichero($rutaFisica);

    $nombreDirectorio = trim($directorio) === '' || trim($directorio) === '/' ? '/' : basename($directorio);

    $stmtRuta = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario LIMIT 1");
    $stmtRuta->execute([
        ':nombre' => $nombreDirectorio,
        ':propietario' => $userID
    ]);
    $rutaID = $stmtRuta->fetchColumn();

    if ($rutaID) {
        $stmtTamaño = $pdo->prepare("SELECT id, tamaño FROM archivos WHERE nombre = :nombre AND propietario = :propietario AND ruta = :ruta");
        $stmtTamaño->execute([
            ':nombre' => $nombreLimpio,
            ':propietario' => $userID,
            ':ruta' => $rutaID
        ]);
        $archivoInfo = $stmtTamaño->fetch(PDO::FETCH_ASSOC);

        if ($archivoInfo) {
            $archivoId = $archivoInfo['id'];
            $tamaño = $archivoInfo['tamaño'];

            notificarEliminacionCompartidos($pdo, $archivoId, 'archivo', $nombreLimpio);
            eliminarComparticionesYNotificaciones($pdo, $archivoId, 'archivo');

            $stmtDelete = $pdo->prepare("DELETE FROM archivos WHERE id = ?");
            $stmtDelete->execute([$archivoId]);

            $stmtUpdate = $pdo->prepare("UPDATE almacenamiento SET almacenamiento_actual = GREATEST(almacenamiento_actual - ?, 0) WHERE propietario = ?");
            $stmtUpdate->execute([$tamaño, $userID]);

            Flight::json(['message' => 'Archivo eliminado correctamente'], 200);
        } else {
            Flight::json(['error' => 'No se pudo obtener el tamaño del archivo de la base de datos.'], 500);
        }
    } else {
        Flight::json(['error' => 'No se encontró el directorio en la base de datos.'], 404);
    }
});

function eliminarComparticionesYNotificaciones(PDO $pdo, int $elementoId, string $tipo): void {
    $campo = $tipo === 'archivo' ? 'archivo' : 'directorio';

    $stmt = $pdo->prepare("SELECT id FROM comparticion WHERE $campo = ?");
    $stmt->execute([$elementoId]);
    $comparticiones = $stmt->fetchAll(PDO::FETCH_COLUMN);

    if ($comparticiones) {
        $inQuery = implode(',', array_fill(0, count($comparticiones), '?'));
        $stmtDelNoti = $pdo->prepare("DELETE FROM notificaciones WHERE comparticion IN ($inQuery)");
        $stmtDelNoti->execute($comparticiones);
    }

    $stmt = $pdo->prepare("DELETE FROM comparticion WHERE $campo = ?");
    $stmt->execute([$elementoId]);
}

function notificarEliminacionCompartidos(PDO $pdo, int $elementoId, string $tipo, string $nombreElemento): void {
    $campo = $tipo === 'archivo' ? 'archivo' : 'directorio';

    $stmt = $pdo->prepare("SELECT id, usuario_destinatario FROM comparticion WHERE $campo = ?");
    $stmt->execute([$elementoId]);
    $comparticiones = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($comparticiones as $comp) {
        $mensaje = "El " . ($tipo === 'archivo' ? "archivo" : "directorio") . " compartido '$nombreElemento' ha sido eliminado.";
        $stmtInsert = $pdo->prepare("INSERT INTO notificaciones (tipo, mensaje, propietario, comparticion) VALUES ('informacion', ?, ?, ?)");
        $stmtInsert->execute([$mensaje, $comp['usuario_destinatario'], $comp['id']]);
    }
}

function obtenerNombreElemento(PDO $pdo, string $tipo, int $id): string {
    $tabla = $tipo === 'archivo' ? 'archivos' : 'directorios';
    $stmt = $pdo->prepare("SELECT nombre FROM $tabla WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetchColumn() ?: '';
}

Flight::route('GET /latest-files', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if ($userData === null || !isset($userData["id"])) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    
    $userID = $userData["id"];

    if (!$userID) {
        Flight::jsonHalt(["message" => "No se pudo obtener el ID del usuario desde el token."], 400);
    }

    try {
        $stmt = $pdo->prepare("
            SELECT nombre, tamaño, fecha, ruta 
            FROM archivos 
            WHERE propietario = :userID 
            ORDER BY fecha DESC 
            LIMIT 6
        ");
        $stmt->execute([':userID' => $userID]);
        $archivos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Mapear archivos para incluir la ruta con nombres
        $archivosConRuta = array_map(function ($archivo) use ($pdo) {
            $rutaNombre = $archivo['ruta'] !== null
                ? obtenerRutaPorNombre($pdo, (int)$archivo['ruta'])
                : '';
            
            return [
                'nombre' => $archivo['nombre'],
                'tamaño' => $archivo['tamaño'],
                'fecha'  => $archivo['fecha'],
                'ruta'   => $rutaNombre
            ];
        }, $archivos);

        Flight::json(['archivos' => $archivosConRuta], 200);

    } catch (PDOException $e) {
        Flight::json(['error' => 'Error al consultar archivos recientes'], 500);
    }
});

Flight::route('GET /favorite-files', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if ($userData === null || !isset($userData["id"])) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    
    $userID = $userData["id"];

    if (!$userID) {
        Flight::jsonHalt(["message" => "No se pudo obtener el ID del usuario desde el token."], 400);
    }

    try {
        $stmt = $pdo->prepare("
            SELECT nombre, tamaño, fecha, ruta 
            FROM archivos 
            WHERE propietario = :userID AND favorito = true
        ");
        $stmt->execute([':userID' => $userID]);
        $archivos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Mapear archivos para incluir la ruta con nombres
        $archivosConRuta = array_map(function ($archivo) use ($pdo) {
            $rutaNombre = $archivo['ruta'] !== null
                ? obtenerRutaPorNombre($pdo, (int)$archivo['ruta'])
                : '';
            
            return [
                'nombre' => $archivo['nombre'],
                'tamaño' => $archivo['tamaño'],
                'fecha'  => $archivo['fecha'],
                'directorio' => $rutaNombre
            ];
        }, $archivos);

        Flight::json(['favoritos' => $archivosConRuta], 200);

    } catch (PDOException $e) {
        Flight::json(['error' => 'Error al consultar archivos recientes'], 500);
    }
});

function obtenerRutaPorNombre(PDO $pdo, int $rutaID): string {
    
    $nombres = [];

    while ($rutaID !== null) {
        $stmt = $pdo->prepare("SELECT nombre, ruta_padre FROM directorios WHERE id = ?");
        $stmt->execute([$rutaID]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) break;

        array_unshift($nombres, $row['nombre']); // Lo agregamos al principio
        $rutaID = $row['ruta_padre']; // Subimos un nivel
    }

    if (count($nombres) === 1) {
        return '/';
    }

    if (!empty($nombres)) {
        array_shift($nombres); // Quitamos el primer elemento
    }

    return '/'. implode('/', $nombres); // Concatenamos los nombres de los directorios
}

Flight::route('POST /encrypt-upload', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userID = $userData["id"];
    $directorio = trim($_POST['directorio'] ?? '/');

    if (!isset($_FILES['files'])) {
        Flight::json(["error" => "No se recibieron archivos"], 400);
        return;
    }

    $baseDir = '/var/shared/' . $userID;
    $targetDir = $directorio === '/' ? $baseDir : "$baseDir/$directorio";

    if (!is_dir($targetDir)) {
        mkdir($targetDir, 0775, true);
    }

    // 🔐 Obtener clave AES del usuario
    $stmtToken = $pdo->prepare("SELECT token FROM token WHERE propietario = ?");
    $stmtToken->execute([$userID]);
    $claveBase64 = $stmtToken->fetchColumn();

    if (!$claveBase64) {
        Flight::json(["error" => "No se encontró clave de encriptación para el usuario."], 400);
        return;
    }

    // 🧠 Obtener ID del directorio
    $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario LIMIT 1");
    $stmt->execute([
        ':nombre' => $directorio === '/' ? '/' : basename($directorio),
        ':propietario' => $userID
    ]);
    $rutaID = $stmt->fetchColumn();

    // 🧮 Obtener datos de almacenamiento del usuario
    $stmtAlm = $pdo->prepare("SELECT almacenamiento_maximo, almacenamiento_actual FROM almacenamiento WHERE propietario = ?");
    $stmtAlm->execute([$userID]);
    $almacenamiento = $stmtAlm->fetch(PDO::FETCH_ASSOC);

    if (!$almacenamiento) {
        Flight::json(["error" => "No se encontraron datos de almacenamiento del usuario."], 500);
        return;
    }

    $maximo = (int) $almacenamiento['almacenamiento_maximo'];
    $actual = (int) $almacenamiento['almacenamiento_actual'];

    $errors = [];
    $archivosEncriptados = [];
    $totalSizeFinal = 0;

    foreach ($_FILES['files']['tmp_name'] as $index => $tmpPath) {
        $originalName = $_FILES['files']['name'][$index];
        $encryptedName = $originalName . '.cbk';
        $destination = "$targetDir/$encryptedName";
    
        // 📁 Verificar si ya existe un archivo con el mismo nombre
        if (file_exists($destination)) {
            $errors[] = "El archivo $originalName ya existe.";
            continue;
        }
    
        // 🔐 Encriptar el archivo
        if (!aesEncryptFile($tmpPath, $destination, $claveBase64)) {
            $errors[] = "Error al encriptar el archivo $originalName.";
            continue;
        }
    
        // ⚖️ Calcular tamaño real del archivo ya encriptado
        $encryptedSize = filesize($destination);
        if ($encryptedSize === false) {
            $errors[] = "No se pudo obtener el tamaño del archivo encriptado $originalName.";
            unlink($destination);
            continue;
        }
    
        $totalSizeFinal += $encryptedSize;
    
        $archivosEncriptados[] = [
            'nombre' => $encryptedName,
            'ruta' => $rutaID,
            'tamaño' => $encryptedSize,
            'fecha' => date("Y-m-d H:i:s")
        ];
    }    

    // 📏 Verificar si hay espacio suficiente
    if ($actual + $totalSizeFinal > $maximo) {
        // 🧹 Eliminar los archivos encriptados
        foreach ($archivosEncriptados as $archivo) {
            $path = "$targetDir/{$archivo['nombre']}";
            if (file_exists($path)) {
                unlink($path);
            }
        }

        Flight::json(["error" => "No hay suficiente espacio de almacenamiento disponible."], 413);
        return;
    }

    // 💾 Insertar en BD y actualizar almacenamiento_actual
    foreach ($archivosEncriptados as $archivo) {
        $stmtInsert = $pdo->prepare("INSERT INTO archivos (nombre, propietario, ruta, tamaño, fecha) VALUES (?, ?, ?, ?, ?)");
        $stmtInsert->execute([
            $archivo['nombre'],
            $userID,
            $archivo['ruta'],
            $archivo['tamaño'],
            $archivo['fecha']
        ]);
    }

    $nuevoUso = $actual + $totalSizeFinal;
    $stmtUpdate = $pdo->prepare("UPDATE almacenamiento SET almacenamiento_actual = ? WHERE propietario = ?");
    $stmtUpdate->execute([$nuevoUso, $userID]);

    if (!empty($errors)) {
        Flight::json(["message" => "Algunos archivos no se pudieron subir", "errors" => $errors], 207);
    } else {
        Flight::json(["message" => "Archivos encriptados y subidos correctamente."], 200);
    }
});

Flight::route('POST /encrypt-folder-upload', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);

    $userID = $userData["id"];
    $directorio = trim($_POST['directorio'] ?? '/');

    if (!isset($_FILES['files'])) {
        Flight::json(["error" => "No se recibieron archivos"], 400);
        return;
    }

    // 🔍 Obtener almacenamiento actual, máximo y alerta
    $stmtStorage = $pdo->prepare("SELECT almacenamiento_actual, almacenamiento_maximo, tamaño_alerta FROM almacenamiento WHERE propietario = ?");
    $stmtStorage->execute([$userID]);
    $storage = $stmtStorage->fetch(PDO::FETCH_ASSOC);

    if (!$storage) {
        Flight::json(["error" => "No se encontró información de almacenamiento para el usuario."], 400);
        return;
    }

    $actual = (int) $storage['almacenamiento_actual'];
    $maximo = (int) $storage['almacenamiento_maximo'];
    $alerta = (int) $storage['tamaño_alerta'];

    // 📦 Calcular tamaño total de archivos a subir
    $totalSizeToUpload = 0;
    foreach ($_FILES['files']['tmp_name'] as $tmpFile) {
        $fileSize = filesize($tmpFile);
        if ($fileSize !== false) {
            $totalSizeToUpload += $fileSize;
        }
    }

    // ❌ Verificar si excede el límite
    if ($actual + $totalSizeToUpload > $maximo) {
        Flight::json(["error" => "No hay suficiente espacio disponible para subir estos archivos."], 413);
        return;
    }

    $paths = $_POST['paths'] ?? [];
    $isStructured = !empty($paths) && count($paths) === count($_FILES['files']['name']);

    $baseDir = '/var/shared/' . $userID;
    $targetDir = $directorio === '/' ? $baseDir : "$baseDir/$directorio";

    if (!is_dir($targetDir)) {
        mkdir($targetDir, 0775, true);
    }

    $stmtToken = $pdo->prepare("SELECT token FROM token WHERE propietario = ?");
    $stmtToken->execute([$userID]);
    $claveBase64 = $stmtToken->fetchColumn();

    if (!$claveBase64) {
        Flight::json(["error" => "No se encontró clave de encriptación para el usuario."], 400);
        return;
    }

    // Obtener el ID del directorio base "/"
    $stmtBase = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario AND ruta_padre IS NULL LIMIT 1");
    $stmtBase->execute([
        ':nombre' => '/',
        ':propietario' => $userID
    ]);
    $rootID = $stmtBase->fetchColumn();
    if (!$rootID) {
        $stmtInsertRoot = $pdo->prepare("INSERT INTO directorios (nombre, propietario, ruta_padre) VALUES (?, ?, NULL)");
        $stmtInsertRoot->execute(['/', $userID]);
        $rootID = $pdo->lastInsertId();
    }

    // Función para crear directorios anidados en DB
    function createDirectoryStructure($relativePath, $userID, $baseDirID, $pdo, &$dirMap) {
        $parts = explode('/', trim($relativePath, '/'));
        $currentParent = $baseDirID;
        $currentPath = '';

        foreach ($parts as $part) {
            $currentPath .= '/' . $part;

            if (isset($dirMap[$currentPath])) {
                $currentParent = $dirMap[$currentPath];
                continue;
            }

            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ? AND ruta_padre = ?");
            $stmt->execute([$part, $userID, $currentParent]);
            $existingID = $stmt->fetchColumn();

            if ($existingID) {
                $dirMap[$currentPath] = $existingID;
                $currentParent = $existingID;
            } else {
                $stmtInsert = $pdo->prepare("INSERT INTO directorios (nombre, propietario, ruta_padre) VALUES (?, ?, ?)");
                $stmtInsert->execute([$part, $userID, $currentParent]);
                $newID = $pdo->lastInsertId();
                $dirMap[$currentPath] = $newID;
                $currentParent = $newID;
            }
        }

        return $currentParent;
    }

    $dirMap = ['/' => $rootID];
    $errors = [];
    $totalEncryptedSize = 0;

    foreach ($_FILES['files']['tmp_name'] as $index => $tmpPath) {
        $originalName = $_FILES['files']['name'][$index];

        $relativePath = $isStructured ? trim($paths[$index], "/") : $originalName;
        $encryptedName = $originalName . '.cbk';

        $subDirPath = dirname($relativePath);
        $dbDirID = $rootID;

        if ($subDirPath !== '.' && $subDirPath !== '') {
            $dbDirID = createDirectoryStructure($subDirPath, $userID, $rootID, $pdo, $dirMap);
        }

        $destinationPath = "$targetDir/" . dirname($relativePath);
        if (!is_dir($destinationPath)) {
            mkdir($destinationPath, 0775, true);
        }

        $fullPath = "$destinationPath/$encryptedName";

        // Si ya existe, error
        if (file_exists($fullPath)) {
            $errors[] = "El archivo $originalName ya existe.";
            continue;
        }

        if (!aesEncryptFile($tmpPath, $fullPath, $claveBase64)) {
            $errors[] = "Error al encriptar el archivo $originalName.";
            continue;
        }

        $encryptedSize = filesize($fullPath);
        if ($encryptedSize === false) {
            $errors[] = "No se pudo obtener el tamaño de $originalName.";
            unlink($fullPath);
            continue;
        }

        $totalEncryptedSize += $encryptedSize;

        $stmtInsert = $pdo->prepare("INSERT INTO archivos (nombre, propietario, ruta, tamaño) VALUES (?, ?, ?, ?)");
        $stmtInsert->execute([
            $encryptedName,
            $userID,
            $dbDirID,
            $encryptedSize,
        ]);
    }

    // 🔁 Actualizar almacenamiento total
    if ($totalEncryptedSize > 0) {
        $stmtUpdateStorage = $pdo->prepare("UPDATE almacenamiento SET almacenamiento_actual = almacenamiento_actual + ? WHERE propietario = ?");
        $stmtUpdateStorage->execute([$totalEncryptedSize, $userID]);
    }

    // ⚠️ Advertencia si supera el límite de alerta
    if ($actual + $totalEncryptedSize > $alerta && $actual + $totalEncryptedSize <= $maximo) {
        Flight::json([
            "message" => "Carpeta subida y encriptada correctamente, pero se ha superado el umbral de alerta.",
            "alerta" => true,
            "tamaño_alerta" => $alerta,
        ], 200);
        return;
    }

    if (!empty($errors)) {
        Flight::json(["message" => "Algunos archivos no se pudieron subir", "errors" => $errors], 207);
    } else {
        Flight::json(["message" => "Carpeta subida y encriptada correctamente"], 200);
    }
});

Flight::route('POST /download', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No autenticado"], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);

    $userID = $userData["id"];
    $nombre = $_POST['nombre'] ?? null;
    $directorio = $_POST['directorio'] ?? null;

    if (!$nombre || $directorio === null) {
        Flight::json(["message" => "Nombre o directorio faltante"], 400);
        return;
    }

    $baseDir = "/var/shared/$userID";
    $targetPath = $directorio === "/" ? "$baseDir/$nombre" : "$baseDir/$directorio/$nombre";

    $stmt = $pdo->prepare("SELECT token FROM token WHERE propietario = ?");
    $stmt->execute([$userID]);
    $claveBase64 = $stmt->fetchColumn();

    if (!$claveBase64) {
        Flight::json(["message" => "Clave de cifrado no encontrada para el usuario"], 500);
        return;
    }

    if (!file_exists($targetPath)) {
        Flight::json(["message" => "Archivo o directorio no encontrado"], 404);
        return;
    }

    if (is_file($targetPath)) {
        // Extraer nombre sin .cbk si lo tiene
        $nombreLimpio = preg_replace('/\.cbk$/', '', $nombre);

        // Obtener extensión original si existe
        $extension = pathinfo($nombreLimpio, PATHINFO_EXTENSION);
        $baseName = pathinfo($nombreLimpio, PATHINFO_FILENAME);

        $nombreFinal = $extension ? "$baseName.$extension" : $baseName;

        // Desencriptar archivo
        $tempFile = tempnam(sys_get_temp_dir(), 'dec_');
        if (!aesDecryptFile($targetPath, $tempFile, $claveBase64)) {
            Flight::json(["message" => "Error al desencriptar el archivo"], 500);
            return;
        }

        Flight::response()->header("Content-Type", "application/octet-stream");
        Flight::response()->header("Content-Disposition", "attachment; filename=\"$nombreFinal\"");
        readfile($tempFile);
        unlink($tempFile);

    } else if (is_dir($targetPath)) {
        // Crear nombre del archivo ZIP basado en el directorio
        $zipName = basename($targetPath) . '.zip'; // Usar el nombre del directorio como base para el nombre del ZIP
        $zipBase = tempnam(sys_get_temp_dir(), 'zip_');
        $zipPath = $zipBase . '.zip';

        if (!rename($zipBase, $zipPath)) {
            Flight::json(["message" => "No se pudo comenzar la descarga"], 500);
            return;
        }

        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            Flight::json(["message" => "Fallo al crear el ZIP"], 500);
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        $archivosAgregados = 0;

        foreach ($iterator as $fileInfo) {
            if ($fileInfo->isFile()) {
                $inputPath = $fileInfo->getPathname();

                if (strtolower(pathinfo($inputPath, PATHINFO_EXTENSION)) === 'cbk') {
                    // Ruta relativa desde el directorio base
                    $relativePath = substr($inputPath, strlen($targetPath) + 1);

                    // Mantener subdirectorios, quitando solo la extensión .cbk
                    $nombreFinal = preg_replace('/\.cbk$/i', '', $relativePath);

                    $tempFile = tempnam(sys_get_temp_dir(), 'dec_');
                    if (aesDecryptFile($inputPath, $tempFile, $claveBase64)) {
                        $zip->addFile($tempFile, $nombreFinal);
                        $archivosAgregados++;
                    } else {
                        Flight::jsonHalt(["message" => "Fallo al desencriptar"], 500);
                    }
                }
            }
        }

        // Si no se agregó ningún archivo, poner un mensaje en el ZIP
        if ($archivosAgregados === 0) {
            $zip->close(); // Para liberar el recurso aunque no lo usemos
            Flight::json(["message" => "La carpeta no contiene archivos."], 400);
            return;
        }

        if (!$zip->close()) {
            Flight::json(["message" => "Fallo al crear el archivo ZIP"], 500);
            return;
        }

        if (!file_exists($zipPath)) {
            Flight::json(["message" => "Fallo al crear el archivo ZIP"], 500);
            return;
        }

        // Asegurarse de que el navegador descargue el archivo como un archivo .zip
        Flight::response()->header("Content-Type", "application/zip");
        Flight::response()->header("Content-Disposition", "attachment; filename=\"$zipName\"");
        Flight::response()->header("Content-Length", filesize($zipPath));

        readfile($zipPath);
        unlink($zipPath); // limpieza del ZIP
    } else {
        Flight::json(["message" => "Tipo de archivo no compatible"], 400);
    }
});

function aesEncryptFile($inputPath, $outputPath, $claveOriginal): bool{
    $key = hash('sha256', $claveOriginal, true);
    $iv = random_bytes(16); // AES-256 usa IV de 16 bytes

    $data = file_get_contents($inputPath);
    if ($data === false) return false;

    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($encrypted === false) return false;

    // Guardamos el IV al principio del archivo
    return file_put_contents($outputPath, $iv . $encrypted) !== false;
}

function aesDecryptFile(string $inputPath, string $outputPath, string $base64Key): bool {
    $key = hash('sha256', $base64Key, true);

    $encryptedData = file_get_contents($inputPath);
    if ($encryptedData === false || strlen($encryptedData) <= 16) {
        return false;
    }

    $iv = substr($encryptedData, 0, 16); // los primeros 16 bytes son el IV
    $ciphertext = substr($encryptedData, 16); // el resto es el contenido cifrado

    $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        return false;
    }

    return file_put_contents($outputPath, $decrypted) !== false;
}

Flight::route('POST /favorite-file', function () {
    global $pdo;
    // Obtener la cookie de autenticación
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["message" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if ($userData === null || !isset($userData["id"])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userID = $userData["id"];

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $nombre = $data["nombre"] ?? null;
    $directorio = $data["directorio"] ?? null;
    $seleccionado = $data["seleccionado"] ?? null;

    if (!$nombre || $directorio === null || $seleccionado === null) {
        Flight::jsonHalt(["message" => "Faltan parámetros requeridos."], 400);
    }
    
    $nombreLimpio = basename(trim($nombre));
    $directorio = trim($directorio, "/");

    $rutaFisica = $directorio ? basename($directorio) : "/";

    // Buscar el directorio
    $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ?");
    $stmt->execute([$rutaFisica, $userID]);

    $rutaID = $stmt->fetchColumn();

    if (!$rutaID) {
        Flight::json(["message" => "Archivo no encontrado en la base de datos."], 404);
        return;
    }

    // Si el archivo existe y la solicitud es para cambiar el estado a 'favorito'
    if ($seleccionado) {
        $updateStmt = $pdo->prepare("UPDATE archivos SET favorito = true WHERE nombre = ? AND propietario = ? AND ruta = ?");
        $updateStmt->execute([$nombreLimpio, $userID, $rutaID]);
    } else {
        // Si se quiere desmarcar como favorito
        $updateStmt = $pdo->prepare("UPDATE archivos SET favorito = false WHERE nombre = ? AND propietario = ? AND ruta = ?");
        $updateStmt->execute([$nombreLimpio, $userID, $rutaID]);
    }

    Flight::json(["message" => "Estado del archivo actualizado correctamente"], 200);
});

Flight::route('GET /connection-logs', function () {
    global $pdo;

    // Verificar que la cookie existe
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["message" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];

    // Obtener registros de la base de datos
    $stmt = $pdo->prepare("SELECT ip_origen, fecha, estado, navegador FROM registro_conexiones WHERE propietario = ? ORDER BY fecha DESC");
    $stmt->execute([$userID]);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    Flight::json(["logs" => $logs]);
});

Flight::route('GET /get-tree', function () {
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];
    $baseDir = "/var/shared/" . $userID;

    if (!is_dir($baseDir)) {
        Flight::json(["error" => "El directorio del usuario no existe."], 404);
        return;
    }

    $resultados = [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($baseDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $fullPath = $item->getPathname();
        $relativePath = str_replace($baseDir . DIRECTORY_SEPARATOR, '', $fullPath);
        $relativePath = str_replace('\\', '/', $relativePath); // normalizar

        $resultados[] = [
            "path" => $relativePath,
            "type" => $item->isDir() ? "folder" : "file"
        ];
    }

    Flight::json(["items" => $resultados], 200);
});

Flight::route('GET /get-space', function () {
    global $pdo;

    // Leer userid desde cookie
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];

    // Consultar almacenamiento
    $stmt = $pdo->prepare('SELECT almacenamiento_maximo, almacenamiento_actual, tamaño_alerta FROM almacenamiento WHERE propietario = :propietario');
    $stmt->bindParam(':propietario', $userID);
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$result) {
        Flight::json(['error' => 'No se encontró información de almacenamiento para este usuario'], 404);
        return;
    }

    Flight::json($result);
});

Flight::route('POST /update-alert', function() {
    global $pdo;

    // Leer userid desde cookie
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    if (!isset($data["alertValue"])) {
        Flight::jsonHalt(["message" => "El tamaño de alerta es requerido."], 400);
    }

    $alerta = $data["alertValue"];

    if (!is_numeric($alerta)) {
        Flight::json(['error' => 'Valor de alerta inválido'], 400);
        return;
    }

    $alertInBytes = intval($alerta) * 1024 * 1024 * 1024;

    $stmt = $pdo->prepare("UPDATE almacenamiento SET tamaño_alerta = ? WHERE propietario = ?");
    $stmt->execute([$alertInBytes, $userID]);

    Flight::json(['message' => 'Alerta actualizada con éxito']);
});

Flight::route('POST /shared', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $nombre = $data["nombre"] ?? null;
    $tipo = $data["tipo"] ?? null;
    $correos = $data["correos"] ?? null;
    $directorio = $data["directorio"] ?? null;
    $correo = $data["propietario"] ?? null;

    if (!$nombre || !$tipo || !$correos || !$directorio) {
        Flight::json(["message" => "Faltan datos obligatorios."], 400);
        return;
    }

    $directorio = trim($directorio, "/");
    $rutaFisica = $directorio ? basename($directorio) : "/";

    $id = null;
    $esCompartido = false;

    if ($correo) {
        $stmtUsuario = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $stmtUsuario->execute([$correo]);
        $usuarioActualId = $stmtUsuario->fetchColumn();

        if (!$usuarioActualId) {
            Flight::json(["message" => "Usuario no encontrado."], 404);
            return;
        }

        if ($tipo === 'archivo') {
            $stmtDir = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ?");
            $stmtDir->execute([$rutaFisica, $usuarioActualId]);
            $directorioId = $stmtDir->fetchColumn();

            if (!$directorioId) {
                Flight::json(["message" => "Directorio no encontrado."], 404);
                return;
            }

            $stmtArchivo = $pdo->prepare("
                SELECT a.id 
                FROM archivos a
                INNER JOIN comparticion c ON c.archivo = a.id
                WHERE a.nombre = ? 
                  AND a.ruta = ?
                  AND c.usuario_destinatario = ?
                  AND c.permiso = 'copropietario'
                  AND c.estado = 'activo'
                LIMIT 1
            ");
            $stmtArchivo->execute([$nombre, $directorioId, $userID]);
            $id = $stmtArchivo->fetchColumn();
        } else {
            $stmtPadre = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ?");
            $stmtPadre->execute([$rutaFisica, $usuarioActualId]);
            $rutaPadreId = $stmtPadre->fetchColumn();

            if (!$rutaPadreId) {
                Flight::json(["message" => "Ruta padre no encontrada."], 404);
                return;
            }

            $stmtDir = $pdo->prepare("
                SELECT d.id 
                FROM directorios d
                INNER JOIN comparticion c ON c.directorio = d.id
                WHERE d.nombre = ?
                  AND d.ruta_padre = ?
                  AND c.usuario_destinatario = ?
                  AND c.permiso = 'copropietario'
                  AND c.estado = 'activo'
                LIMIT 1
            ");
            $stmtDir->execute([$nombre, $rutaPadreId, $userID]);
            $id = $stmtDir->fetchColumn();
        }

        if (!$id) {
            Flight::json(["message" => "No tienes permisos para compartir este elemento."], 403);
            return;
        }

        $esCompartido = true;
    } else {
        if ($tipo === 'archivo') {
            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ?");
            $stmt->execute([$rutaFisica, $userID]);
            $directorioId = $stmt->fetchColumn();

            if ($directorioId === false) {
                Flight::halt(404, "Directorio no encontrado");
            }

            $stmt = $pdo->prepare("SELECT id FROM archivos WHERE nombre = ? AND ruta = ? AND propietario = ?");
            $stmt->execute([$nombre, $directorioId, $userID]);
        } else {
            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND ruta_padre = (SELECT id FROM directorios WHERE nombre = ? AND propietario = ?) AND propietario = ?");
            $stmt->execute([$nombre, $rutaFisica, $userID, $userID]);
        }

        $id = $stmt->fetchColumn();

        if (!$id) {
            Flight::halt(404, "No se encontró el elemento a compartir");
        }
    }

    $stmtExistentes = $pdo->prepare("
        SELECT usuario_destinatario, permiso 
        FROM comparticion 
        WHERE estado = 'activo' 
        AND " . ($esCompartido ? "propietario = ?" : "1=1") . "
        AND " . ($tipo === 'archivo' ? "archivo = ?" : "directorio = ?")
    );

    $esCompartido ? $stmtExistentes->execute([$userID, $id]) : $stmtExistentes->execute([$id]);
    $existentes = $stmtExistentes->fetchAll(PDO::FETCH_KEY_PAIR);

    $procesados = [];
    $compartidos = [];

    foreach ($correos as $entry) {
        $correoDest = $entry["correo"] ?? null;
        $permiso = $entry["permiso"] ?? "lector";

        if (!$correoDest || !in_array($permiso, ["copropietario", "lector"])) {
            $compartidos[] = [
                "email" => $correoDest,
                "estado" => "fallo",
                "razon" => "Correo inválido o permiso no permitido"
            ];
            continue;
        }

        $stmtUser = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $stmtUser->execute([$correoDest]);
        $destinatarioId = $stmtUser->fetchColumn();

        if (!$destinatarioId) {
            $compartidos[] = [
                "email" => $correoDest,
                "estado" => "fallo",
                "razon" => "Usuario no encontrado"
            ];
            continue;
        }

        if ($correo && $destinatarioId == $usuarioActualId) {
            $compartidos[] = [
                "email" => $correoDest,
                "estado" => "fallo",
                "razon" => "No puedes compartir con el propietario real"
            ];
            continue;
        }

        $procesados[] = $destinatarioId;

        if (array_key_exists($destinatarioId, $existentes)) {
            if ($existentes[$destinatarioId] !== $permiso) {
                $update = $pdo->prepare("
                    UPDATE comparticion 
                    SET permiso = ?
                    WHERE usuario_destinatario = ? AND " . ($tipo === 'archivo' ? "archivo = ?" : "directorio = ?")
                );
                $update->execute([$permiso, $destinatarioId, $id]);

                $compartidos[] = [
                    "email" => $correoDest,
                    "estado" => "actualizado",
                    "razon" => "Permiso modificado"
                ];
            } else {
                $compartidos[] = [
                    "email" => $correoDest,
                    "estado" => "sin cambios"
                ];
            }
        } else {
            $insert = $pdo->prepare("
                INSERT INTO comparticion (propietario, permiso, estado, usuario_destinatario, archivo, directorio)
                VALUES (?, ?, 'activo', ?, ?, ?)
            ");
            if ($tipo === 'archivo') {
                $insert->execute([$userID, $permiso, $destinatarioId, $id, null]);
            } else {
                $insert->execute([$userID, $permiso, $destinatarioId, null, $id]);
            }

            $comparticionId = $pdo->lastInsertId();
            $mensajeNotif = "Has recibido acceso " . ($permiso === 'copropietario' ? "como copropietario" : "como lector") . " al $tipo '$nombre'.";

            $noti = $pdo->prepare("
                INSERT INTO notificaciones (tipo, mensaje, propietario, comparticion)
                VALUES ('informacion', ?, ?, ?)
            ");
            $noti->execute([$mensajeNotif, $destinatarioId, $comparticionId]);

            $compartidos[] = [
                "email" => $correoDest,
                "estado" => "nuevo"
            ];
        }
    }

    foreach ($existentes as $revocarId => $permiso) {
        if (!in_array($revocarId, $procesados)) {
            $revocar = $pdo->prepare("
                UPDATE comparticion 
                SET estado = 'revocado'
                WHERE usuario_destinatario = ? AND " . ($tipo === 'archivo' ? "archivo = ?" : "directorio = ?")
            );
            $revocar->execute([$revocarId, $id]);

            $compartidos[] = [
                "email" => $revocarId,
                "estado" => "revocado",
                "razon" => "Revocado por el propietario real"
            ];
        }
    }

    Flight::json([
        "message" => "Compartición actualizada",
        "resultados" => $compartidos
    ], 200);
});

Flight::route('GET /shared-owner', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $usuarioActualId = $userData["id"];

    // Obtener compartidos del propietario con el usuario que consulta
    $stmtCompartidos = $pdo->prepare("
    SELECT 
        c.permiso,
        c.archivo,
        c.directorio,
        u.email AS destinatario_email,
        a.nombre AS nombre_archivo,
        a.fecha AS fecha_archivo,
        a.tamaño AS tamaño_archivo,
        d.nombre AS nombre_directorio,
        d.fecha_creacion AS fecha_directorio
    FROM comparticion c
    INNER JOIN usuarios u ON c.usuario_destinatario = u.id
    LEFT JOIN archivos a ON c.archivo = a.id
    LEFT JOIN directorios d ON c.directorio = d.id
    WHERE c.propietario = ?
      AND c.estado = 'activo'
      AND (
        (c.archivo IS NOT NULL AND a.propietario != ?) 
        OR 
        (c.directorio IS NOT NULL AND d.propietario != ?)
      )
    ");
    $stmtCompartidos->execute([$usuarioActualId, $usuarioActualId, $usuarioActualId]);

    $registros = $stmtCompartidos->fetchAll(PDO::FETCH_ASSOC);

    $resultado = [];

    foreach ($registros as $row) {
        if ($row["archivo"]) {
            $resultado[] = [
                "nombre" => $row["nombre_archivo"],
                "fecha" => $row["fecha_archivo"],
                "tamaño" => (int) $row["tamaño_archivo"],
                "permiso" => $row["permiso"],
                "destinatario_email" => $row["destinatario_email"],
                "tipo" => "archivo"
            ];
        } elseif ($row["directorio"]) {
            $resultado[] = [
                "nombre" => $row["nombre_directorio"],
                "fecha" => $row["fecha_directorio"],
                "tamaño" => null,
                "permiso" => $row["permiso"],
                "destinatario_email" => $row["destinatario_email"],
                "tipo" => "directorio"
            ];
        }
    }

    Flight::json([
        "message" => "Compartidos encontrados",
        "compartidos" => $resultado
    ], 200);
});

Flight::route('POST /shared-files', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $directorio = $data["directorio"] ?? null;

    if (!$directorio) {
        Flight::json(["message" => "Faltan datos obligatorios."], 400);
        return;
    }

    $directorio = trim($directorio, "/");
    $rutaFisica = $directorio ? basename($directorio) : "/";

    $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ?");
    $stmt->execute([$rutaFisica, $userID]);
    $directorioId = $stmt->fetchColumn();

    if ($directorioId === false) {
        Flight::halt(404, "Directorio no encontrado");
    }

    // Buscar archivos compartidos con ese usuario en ese directorio
    $stmt = $pdo->prepare("
        (
            SELECT 
                a.nombre AS nombre,
                a.fecha AS fecha,
                a.tamaño AS tamaño,
                c.permiso AS permiso,
                u.email AS destinatario_email,
                'archivo' AS tipo
            FROM comparticion c
            JOIN archivos a ON c.archivo = a.id
            JOIN usuarios u ON c.usuario_destinatario = u.id
            WHERE c.propietario = ? 
              AND a.ruta = ? 
              AND c.estado = 'activo'
        )
        UNION ALL
        (
            SELECT 
                d.nombre AS nombre,
                d.fecha_creacion AS fecha,
                NULL AS tamaño,
                c.permiso AS permiso,
                u.email AS destinatario_email,
                'directorio' AS tipo
            FROM comparticion c
            JOIN directorios d ON c.directorio = d.id
            JOIN usuarios u ON c.usuario_destinatario = u.id
            WHERE c.propietario = ? 
              AND d.ruta_padre = ? 
              AND c.estado = 'activo'
        )
    ");
    $stmt->execute([$userID, $directorioId, $userID, $directorioId]);

    $compartidos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    Flight::json($compartidos);
});

Flight::route('POST /unshared', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData["id"];
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $nombre = $data["nombre"] ?? null;
    $tipo = $data["tipo"] ?? null;
    $directorio = $data["directorio"] ?? null;

    if (!$nombre || !$tipo || !$directorio) {
        Flight::json(["message" => "Faltan datos obligatorios."], 400);
        return;
    }

    $directorio = trim($directorio, "/");
    $rutaFisica = $directorio ? basename($directorio) : "/";

    try {
        // Obtener ID del elemento (archivo o directorio)
        if ($tipo === 'archivo') {
            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = ? AND propietario = ?");
            $stmt->execute([$rutaFisica, $userID]);
            $directorioId = $stmt->fetchColumn();

            if ($directorioId === false) {
                Flight::halt(404, "Directorio no encontrado");
            }

            $stmt = $pdo->prepare("SELECT id, nombre FROM archivos WHERE nombre = ? AND ruta = ? AND propietario = ?");
            $stmt->execute([$nombre, $directorioId, $userID]);
        } else {
            $stmt = $pdo->prepare("
                SELECT d1.id, d1.nombre 
                FROM directorios d1
                WHERE d1.nombre = ? 
                AND d1.ruta_padre = (
                    SELECT id FROM directorios WHERE nombre = ? AND propietario = ?
                ) 
                AND d1.propietario = ?
            ");
            $stmt->execute([$nombre, $rutaFisica, $userID, $userID]);
        }

        $elemento = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$elemento) {
            Flight::halt(404, "No se encontró el elemento a compartir");
        }

        $id = $elemento['id'];
        $nombreReal = $elemento['nombre']; // <-- Este nombre es confiable

        // Obtener todas las comparticiones activas para ese elemento
        $stmt = $pdo->prepare("
            SELECT id, permiso, usuario_destinatario 
            FROM comparticion 
            WHERE propietario = ? 
            AND " . ($tipo === 'archivo' ? "archivo = ?" : "directorio = ?") . " 
            AND estado != 'revocado'
        ");
        $stmt->execute([$userID, $id]);
        $currentData = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Revocar la compartición
        $update = $pdo->prepare("
            UPDATE comparticion 
            SET estado = 'revocado'
            WHERE " . ($tipo === 'archivo' ? "archivo = ?" : "directorio = ?")
        );
        $update->execute([$id]);

        // Enviar notificación solo a los usuarios que tenían acceso a este elemento
        foreach ($currentData as $data) {
            $mensajeNotif = "Te han quitado el acceso " . ($data["permiso"] === 'copropietario' ? "como copropietario" : "como lector") .
                " al " . ($tipo === 'archivo' ? "archivo" : "directorio") . " '$nombreReal'.";

            $noti = $pdo->prepare("
                INSERT INTO notificaciones (tipo, mensaje, propietario, comparticion)
                VALUES ('informacion', ?, ?, ?)
            ");
            $noti->execute([$mensajeNotif, $data["usuario_destinatario"], $data["id"]]);
        }

        Flight::json(["message" => "Compartición revocada y notificaciones enviadas"], 200);

    } catch (PDOException $e) {
        Flight::json(["error" => "Error en la base de datos: " . $e->getMessage()], 500);
    } catch (Exception $e) {
        Flight::json(["error" => "Error inesperado: " . $e->getMessage()], 500);
    }
});

Flight::route('GET /notifications', function () {
    global $pdo;

    // Validar token JWT desde la cookie
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["message" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded['data'];
    if (!isset($userData['id'])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData['id'];

    // Obtener parámetros opcionales para filtros
    $soloNoLeidas = Flight::request()->query['no_leidas'] ?? false;

    try {
        $sql = "SELECT id, tipo, mensaje, fecha_creacion, leida 
                FROM notificaciones 
                WHERE propietario = :userID";

        if ($soloNoLeidas === "true") {
            $sql .= " AND leida = 0";
        }

        $sql .= " ORDER BY fecha_creacion DESC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':userID' => $userID]);

        $notificaciones = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Convertir leida a booleano (true/false)
        $notificaciones = array_map(function ($notificacion) {
            $notificacion['leida'] = (bool) $notificacion['leida'];  // Convertir a booleano
            return $notificacion;
        }, $notificaciones);

        Flight::json(["notificaciones" => $notificaciones], 200);
    } catch (PDOException $e) {
        Flight::json(["error" => "Error al obtener notificaciones: " . $e->getMessage()], 500);
    }
});

Flight::route('POST /read-notify', function(){
    global $pdo;

    // Validar token JWT desde la cookie
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["message" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded['data'];
    if (!isset($userData['id'])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData['id'];
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $id = (int) $data["id"] ?? null;

    if (!$id) {
        Flight::json(["message" => "Faltan datos obligatorios."], 400);
        return;
    }

    $stmt = $pdo->prepare("UPDATE notificaciones SET leida = true, fecha_lectura = NOW() WHERE id = ? AND propietario = ?");
    if ($stmt->execute([$id, $userID])) {
        Flight::json(["message" => "Se marcó como leída la notificación"], 200);
    } else {
        Flight::json(["message" => "No se puedo marcar como leída la notificación"], 500);
    }
});

Flight::route('GET /shared-files', function () {
    global $pdo;

    // Validar token JWT desde la cookie
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["message" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded['data'];
    if (!isset($userData['id'])) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $userID = $userData['id'];

    try {
        // Obtener archivos y directorios compartidos con el usuario
        $sql = "
            SELECT 
                c.id AS comparticion_id,
                c.fecha_comparticion,
                c.permiso,
                c.estado,
                u.email AS propietario_email,
                d.id AS directorio_id,
                d.nombre AS directorio_nombre,
                d.ruta_padre AS directorio_ruta_padre,
                a.id AS archivo_id,
                a.nombre AS archivo_nombre,
                a.tamaño AS archivo_tamaño,
                a.fecha AS archivo_fecha,
                d.nombre AS directorio_nombre,
                d.ruta_padre AS directorio_ruta_padre
            FROM comparticion c
            LEFT JOIN archivos a ON c.archivo = a.id
            LEFT JOIN directorios d ON c.directorio = d.id
            LEFT JOIN usuarios u ON c.propietario = u.id
            WHERE c.usuario_destinatario = :userID
            AND c.estado = 'activo'  -- Solo consideramos comparticiones activas
            ORDER BY c.fecha_comparticion DESC
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':userID' => $userID]);

        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Modificar las rutas de directorios para ser relativos a la raíz
        foreach ($result as &$compartido) {
            // Si es un archivo compartido
            if ($compartido['archivo_id']) {
                // Para los archivos, mostramos el nombre y la ruta del directorio al que pertenece
                $compartido['directorio_ruta'] = getDirectorioBase($compartido['directorio_ruta_padre']);
            }
            // Si es un directorio compartido
            if ($compartido['directorio_id']) {
                // Para los directorios, simplemente mostramos la ruta completa
                $compartido['directorio_ruta'] = getDirectorioBase($compartido['directorio_ruta_padre']);
            }
        }

        // Devolver los resultados como respuesta JSON
        Flight::json(["comparticiones" => $result], 200);
    } catch (PDOException $e) {
        Flight::json(["error" => "Error al obtener los archivos y directorios compartidos: " . $e->getMessage()], 500);
    }
});

// Función para obtener el directorio base de la ruta
function getDirectorioBase($ruta_padre) {
    // Aquí se debería implementar la lógica para convertir la ruta de padre en un directorio base
    // Por ejemplo, puedes hacer una consulta a la base de datos para recuperar la ruta completa
    global $pdo;
    $sql = "SELECT nombre FROM directorios WHERE id = :ruta_padre";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':ruta_padre' => $ruta_padre]);
    $directorio = $stmt->fetch(PDO::FETCH_ASSOC);

    return $directorio ? $directorio['nombre'] : '/';  // Si no hay, devolver 'Raíz'
}

Flight::route('POST /shared-dir', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::jsonHalt(["message" => "No se encontró la cookie de autenticación."], 401);
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::jsonHalt(["message" => "Token inválido o expirado."], 401);
    }

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    if (!isset($data["directorio"]) || !isset($data["email"])) {
        Flight::jsonHalt(["message" => "El email y el directorio son requeridos."], 400);
    }

    $directorio = trim($data["directorio"], "/");
    $ownerEmail = $data["email"];

    $currentUser = (array) $decoded["data"];
    $currentUserId = $currentUser["id"] ?? null;

    if (!$currentUserId) {
        Flight::jsonHalt(["message" => "No se pudo obtener el ID del usuario desde el token."], 400);
    }

    // Obtener ID del dueño del recurso
    $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
    $stmt->execute([$ownerEmail]);
    $owner = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$owner) {
        Flight::jsonHalt(["message" => "No se encontró el usuario con ese email."], 404);
    }

    $ownerId = $owner['id'];

    // Verificar si algún padre está compartido
    $pathParts = explode("/", $directorio);
    $foundSharedParent = false;
    $permissionType = null;

    while (count($pathParts) > 0) {
        $possiblePath = implode("/", $pathParts);

        $stmt = $pdo->prepare("SELECT id FROM directorios WHERE propietario = ? AND nombre = ?");
        $stmt->execute([$ownerId, $possiblePath]);
        $dir = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($dir) {
            $directoryId = $dir['id'];

            $stmt = $pdo->prepare("SELECT permiso FROM comparticion WHERE directorio = ? AND usuario_destinatario = ? AND estado = 'activo'");
            $stmt->execute([$directoryId, $currentUserId]);
            $shared = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($shared) {
                $foundSharedParent = true;
                $permissionType = $shared['permiso'];
                break;
            }
        }

        array_pop($pathParts);
    }

    if (!$foundSharedParent) {
        Flight::jsonHalt(["message" => "No tienes acceso a este directorio."], 403);
    }

    // Escanear la ruta solicitada
    $rutaRelativa = $ownerId . "/" . $directorio;
    $fm = new FileManager();
    $contents = $fm->scanDirectory($rutaRelativa);

    if (!$contents) {
        Flight::jsonHalt(["message" => "Error escaneando el directorio."], 500);
    }

    // 🔥 Ahora añadimos el permiso a cada ítem del contenido
    $finalContent = [];

    if (isset($contents['contenido']) && is_array($contents['contenido'])) {
        foreach ($contents['contenido'] as $item) {
            $item['permiso'] = $permissionType; // añadimos permiso a cada elemento
            $finalContent[] = $item;
        }
    } else if (is_array($contents)) {
        foreach ($contents as $item) {
            $item['permiso'] = $permissionType; // en caso de que no haya clave 'contenido'
            $finalContent[] = $item;
        }
    }

    // Respondemos
    Flight::json([
        "contenido" => $finalContent
    ], 200);
});

Flight::route('POST /shared-download', function () {
    global $pdo;

    // Validación del JWT en cookie
    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No autenticado"], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    if (!isset($userData["id"])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $requesterID = $userData["id"];

    // Obtener datos desde POST
    $email = $_POST['email'] ?? null;
    $nombre = $_POST['nombre'] ?? null;
    $directorio = $_POST['directoryName'] ?? null;

    if (!$email || !$nombre || $directorio === null) {
        Flight::json(["message" => "Faltan parámetros requeridos (email, nombre o directorio)"], 400);
        return;
    }

    // Obtener el ID del usuario dueño
    $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
    $stmt->execute([$email]);
    $ownerID = $stmt->fetchColumn();

    if (!$ownerID) {
        Flight::json(["message" => "Usuario destino no encontrado"], 404);
        return;
    }

    $baseDir = "/var/shared/$ownerID";
    $targetPath = $directorio === "/" ? "$baseDir/$nombre" : "$baseDir/$directorio/$nombre";

    $stmt = $pdo->prepare("SELECT token FROM token WHERE propietario = ?");
    $stmt->execute([$ownerID]);
    $claveBase64 = $stmt->fetchColumn();

    if (!$claveBase64) {
        Flight::json(["message" => "Clave de cifrado no encontrada para el usuario"], 500);
        return;
    }

    if (!file_exists($targetPath)) {
        Flight::json(["message" => $targetPath], 404);
        return;
    }

    // Funciones de verificación
    function archivoCompartido($nombreArchivo, $ownerID, $directorioRutaID, $pdo) {
        $stmt = $pdo->prepare("SELECT id, ruta FROM archivos WHERE nombre = :nombre AND propietario = :propietario AND ruta = :ruta");
        $stmt->execute([
            ':nombre' => $nombreArchivo,
            ':propietario' => $ownerID,
            ':ruta' => $directorioRutaID
        ]);
    
        $archivo = $stmt->fetch(PDO::FETCH_ASSOC);
    
        if (!$archivo) return false;
    
        // Verificar si el archivo está compartido directamente
        $stmtComp = $pdo->prepare("SELECT 1 FROM comparticion WHERE archivo = :id AND estado = 'activo'");
        $stmtComp->execute([':id' => $archivo['id']]);
        if ($stmtComp->fetch()) return true;
    
        // Si no, verificar si el directorio o sus padres están compartidos
        return directorioCompartidoPorID($archivo['ruta'], $pdo);
    }    

    function obtenerIDDirectorio($ownerID, $nombreDirectorio, $pdo) {
        if ($nombreDirectorio === "/") {
            // Buscar el directorio raíz
            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = '/' AND propietario = :propietario AND ruta_padre IS NULL");
        } else {
            // Buscar un directorio normal
            $stmt = $pdo->prepare("SELECT id FROM directorios WHERE nombre = :nombre AND propietario = :propietario");
            $stmt->execute([
                ':nombre' => basename($nombreDirectorio),
                ':propietario' => $ownerID
            ]);
            return $stmt->fetchColumn();
        }
    
        $stmt->execute([':propietario' => $ownerID]);
        return $stmt->fetchColumn();
    }    
     
    function directorioCompartidoPorID($idDirectorio, $pdo) {
        if (!$idDirectorio) return false;
    
        $stmt = $pdo->prepare("SELECT id, ruta_padre FROM directorios WHERE id = :id");
        $stmt->execute([':id' => $idDirectorio]);
        $directorio = $stmt->fetch(PDO::FETCH_ASSOC);
    
        while ($directorio) {
            $stmtComp = $pdo->prepare("SELECT 1 FROM comparticion WHERE directorio = :id AND estado = 'activo'");
            $stmtComp->execute([':id' => $directorio['id']]);
            if ($stmtComp->fetch()) return true;
    
            if (!$directorio['ruta_padre']) break;
    
            $stmt = $pdo->prepare("SELECT id, ruta_padre FROM directorios WHERE id = :id");
            $stmt->execute([':id' => $directorio['ruta_padre']]);
            $directorio = $stmt->fetch(PDO::FETCH_ASSOC);
        }
    
        return false;
    }    

    function directorioCompartido($nombreDirectorio, $pdo) {
        $stmt = $pdo->prepare("SELECT id, ruta_padre FROM directorios WHERE nombre = :nombre");
        $stmt->execute([':nombre' => $nombreDirectorio]);
        $directorio = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$directorio) return false;

        return directorioCompartidoPorID($directorio['id'], $pdo);
    }

    // Verificación de permisos
    if (is_file($targetPath)) {
        $directorioRutaID = obtenerIDDirectorio($ownerID, $directorio, $pdo);
        if (!archivoCompartido($nombre, $ownerID, $directorioRutaID, $pdo)) {
            Flight::json(["message" => "No autorizado. El archivo no está compartido ni pertenece a un directorio compartido."], 403);
            return;
        }
    } else if (is_dir($targetPath)) {
        if (!directorioCompartido(basename($targetPath), $pdo)) {
            Flight::json(["message" => "No autorizado. El directorio no está compartido."], 403);
            return;
        }
    } else {
        Flight::json(["message" => "Tipo de archivo no compatible"], 400);
        return;
    }

    // Procesos de descarga normales (como ya tenías)...
    if (is_file($targetPath)) {
        $nombreLimpio = preg_replace('/\.cbk$/', '', $nombre);
        $extension = pathinfo($nombreLimpio, PATHINFO_EXTENSION);
        $baseName = pathinfo($nombreLimpio, PATHINFO_FILENAME);
        $nombreFinal = $extension ? "$baseName.$extension" : $baseName;

        $tempFile = tempnam(sys_get_temp_dir(), 'dec_');
        if (!aesDecryptFile($targetPath, $tempFile, $claveBase64)) {
            Flight::json(["message" => "Error al desencriptar el archivo"], 500);
            return;
        }

        Flight::response()->header("Content-Type", "application/octet-stream");
        Flight::response()->header("Content-Disposition", "attachment; filename=\"$nombreFinal\"");
        readfile($tempFile);
        unlink($tempFile);
    } else if (is_dir($targetPath)) {
        $zipName = basename($targetPath) . '.zip';
        $zipBase = tempnam(sys_get_temp_dir(), 'zip_');
        $zipPath = $zipBase . '.zip';

        if (!rename($zipBase, $zipPath)) {
            Flight::json(["message" => "No se pudo comenzar la descarga"], 500);
            return;
        }

        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            Flight::json(["message" => "Fallo al crear el ZIP"], 500);
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        $archivosAgregados = 0;
        foreach ($iterator as $fileInfo) {
            if ($fileInfo->isFile()) {
                $inputPath = $fileInfo->getPathname();
                if (strtolower(pathinfo($inputPath, PATHINFO_EXTENSION)) === 'cbk') {
                    $relativePath = substr($inputPath, strlen($targetPath) + 1);
                    $nombreFinal = preg_replace('/\.cbk$/i', '', $relativePath);

                    $tempFile = tempnam(sys_get_temp_dir(), 'dec_');
                    if (aesDecryptFile($inputPath, $tempFile, $claveBase64)) {
                        $zip->addFile($tempFile, $nombreFinal);
                        $archivosAgregados++;
                    } else {
                        Flight::jsonHalt(["message" => "Fallo al desencriptar"], 500);
                    }
                }
            }
        }

        if ($archivosAgregados === 0) {
            $zip->close();
            Flight::json(["message" => "La carpeta no contiene archivos."], 400);
            return;
        }

        if (!$zip->close()) {
            Flight::json(["message" => "Fallo al crear el archivo ZIP"], 500);
            return;
        }

        if (!file_exists($zipPath)) {
            Flight::json(["message" => "Fallo al crear el archivo ZIP"], 500);
            return;
        }

        Flight::response()->header("Content-Type", "application/zip");
        Flight::response()->header("Content-Disposition", "attachment; filename=\"$zipName\"");
        Flight::response()->header("Content-Length", filesize($zipPath));

        readfile($zipPath);
        unlink($zipPath);
    } else {
        Flight::json(["message" => "Tipo de archivo no compatible"], 400);
    }
});

Flight::route('POST /revoke-share', function () {
    global $pdo;

    if (!isset($_COOKIE['auth'])) {
        Flight::json(["error" => "No se encontró la cookie de autenticación."], 401);
        return;
    }

    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    $usuarioActualId = $userData["id"] ?? null;

    if (!$usuarioActualId) {
        Flight::json(["message" => "Usuario no válido."], 401);
        return;
    }

    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    $emailPropietario = $data["propietario"] ?? null;
    $tipo = $data["tipo"] ?? null;
    $nombre = $data["nombre"] ?? null;

    if (!$emailPropietario || !$tipo || !$nombre) {
        Flight::json(["message" => "Faltan datos requeridos (propietario, tipo, nombre)."], 400);
        return;
    }

    // Buscar ID del propietario por email
    $stmtUsuario = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
    $stmtUsuario->execute([$emailPropietario]);
    $propietarioId = $stmtUsuario->fetchColumn();

    if (!$propietarioId) {
        Flight::json(["message" => "Propietario no encontrado."], 404);
        return;
    }

    // Buscar los registros compartidos usando la misma consulta
    $stmt = $pdo->prepare("
        SELECT 
            c.id,
            c.archivo,
            c.directorio,
            a.nombre AS nombre_archivo,
            d.nombre AS nombre_directorio
        FROM comparticion c
        INNER JOIN usuarios u ON c.usuario_destinatario = u.id
        LEFT JOIN archivos a ON c.archivo = a.id
        LEFT JOIN directorios d ON c.directorio = d.id
        WHERE c.propietario = ?
          AND c.estado = 'activo'
          AND (
            (c.archivo IS NOT NULL AND a.propietario = ?) 
            OR 
            (c.directorio IS NOT NULL AND d.propietario = ?)
          )
    ");
    $stmt->execute([$usuarioActualId, $propietarioId, $propietarioId]);
    $registros = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $idsARevocar = [];

    foreach ($registros as $r) {
        if ($tipo === 'archivo' && $r['archivo'] && $r['nombre_archivo'] === $nombre) {
            $idsARevocar[] = $r['id'];
        } elseif ($tipo === 'directorio' && $r['directorio'] && $r['nombre_directorio'] === $nombre) {
            $idsARevocar[] = $r['id'];
        }
    }

    if (empty($idsARevocar)) {
        Flight::json(["message" => "No se encontraron comparticiones para revocar."], 404);
        return;
    }

    // Revocar todos los registros encontrados
    $placeholders = implode(',', array_fill(0, count($idsARevocar), '?'));
    $stmtUpdate = $pdo->prepare("UPDATE comparticion SET estado = 'revocado' WHERE id IN ($placeholders)");
    $stmtUpdate->execute($idsARevocar);

    Flight::json([
        "message" => "Compartición(es) revocada(s) correctamente.",
        "revocados" => count($idsARevocar)
    ], 200);
});

Flight::route('POST /create-group', function () {
    global $pdo;

    // Obtén el JSON enviado
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Verifica si el JSON contiene los datos necesarios
    if (!isset($data['name']) || !isset($data['description']) || !isset($data['emails']) || !is_array($data['emails'])) {
        Flight::json(['error' => 'Faltan parámetros en el JSON'], 400);
        return;
    }

    // Obtener la cookie (ID del usuario autenticado)
    $jwt = $_COOKIE['auth'];
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    $usuarioActualId = $userData["id"] ?? null;

    // Obtener el email del usuario autenticado
    $stmt = $pdo->prepare("SELECT email FROM usuarios WHERE id = ?");
    $stmt->execute([$usuarioActualId]);
    $usuarioActual = $stmt->fetch(PDO::FETCH_ASSOC);
    $usuarioActualEmail = $usuarioActual['email'] ?? null;

    // Verifica si el email del usuario actual está en el array de correos
    if (!in_array($usuarioActualEmail, $data['emails'])) {
        Flight::json(['error' => 'El correo del usuario autenticado no está en la lista de correos.'], 400);
        return;
    }

    // Ingresar el grupo en la tabla grupos
    $stmt = $pdo->prepare("INSERT INTO grupos (nombre, descripcion) VALUES (?, ?)");
    $stmt->execute([$data['name'], $data['description']]);
    $grupoId = $pdo->lastInsertId();  // Obtén el ID del nuevo grupo

    // Insertar los usuarios en la tabla de usuarios si no existen
    foreach ($data['emails'] as $email) {
        $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $stmt->execute([$email]);
        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

        // Si el usuario no existe, lo insertamos
        if (!$usuario) {
            Flight::jsonHalt(['error' => 'Algunos correos no existen.'], 400);
        } else {
            $usuarioId = $usuario['id']; // Si ya existe, usamos su ID
        }

        // Ahora asociamos el usuario con el grupo en usuarios_grupos
        $stmt = $pdo->prepare("INSERT INTO usuarios_grupos (usuario, grupo) VALUES (?, ?)");
        $stmt->execute([$usuarioId, $grupoId]);
    }

    // Respuesta de éxito
    Flight::json(['message' => 'Grupo creado y usuarios asociados'], 200);
});

Flight::route('GET /groups', function () use ($pdo) {
    // Obtener el JWT de la cookie
    $jwt = $_COOKIE['auth'] ?? null;

    // Si no se encuentra el token, devolver error
    if (!$jwt) {
        Flight::json(['error' => 'Token no proporcionado en la cookie'], 401);
        return;
    }

    // Decodificar el JWT
    $decoded = JWTHandler::decode($jwt);

    // Si el token es inválido o expirado
    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(['error' => 'Token inválido o expirado'], 401);
        return;
    }

    // Obtener el ID del usuario
    $userData = (array) $decoded["data"];
    $usuarioActualId = $userData["id"] ?? null;

    // Verificar si el ID del usuario está presente
    if (!$usuarioActualId) {
        Flight::json(['error' => 'Usuario no encontrado en el token'], 401);
        return;
    }

    // Consultar los grupos en los que el usuario está inscrito, junto con los correos de todos los usuarios en esos grupos
    $stmt = $pdo->prepare("
        SELECT g.id, g.nombre, g.descripcion, u.email
        FROM grupos g
        JOIN usuarios_grupos ug ON g.id = ug.grupo
        JOIN usuarios u ON ug.usuario = u.id
        WHERE ug.grupo IN (
            SELECT grupo 
            FROM usuarios_grupos 
            WHERE usuario = ?
        )
    ");
    $stmt->execute([$usuarioActualId]);

    // Obtener los grupos del usuario, junto con los correos
    $grupos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Si no tiene grupos, devolver mensaje de error
    if (empty($grupos)) {
        Flight::json(['message' => 'No estás inscrito en ningún grupo'], 200);
        return;
    }

    // Organizar los datos para que cada grupo contenga los correos de los usuarios
    $gruposConCorreos = [];
    foreach ($grupos as $grupo) {
        $grupoId = $grupo['id'];
        if (!isset($gruposConCorreos[$grupoId])) {
            $gruposConCorreos[$grupoId] = [
                'id' => $grupoId,
                'nombre' => $grupo['nombre'],
                'descripcion' => $grupo['descripcion'],
                'emails' => []
            ];
        }
        $gruposConCorreos[$grupoId]['emails'][] = $grupo['email'];
    }

    // Convertir el arreglo de grupos con los correos a un formato adecuado
    $gruposFinal = array_values($gruposConCorreos);

    // Devolver los grupos con los correos de los usuarios asociados
    Flight::json(['grupos' => $gruposFinal], 200);
});

Flight::route('POST /delete-group', function () {
    global $pdo;

    // Leer el JSON con el nombre del grupo
    $data = json_decode(file_get_contents('php://input'), true);
    if (!isset($data['name'])) {
        Flight::json(['error' => 'Falta el nombre del grupo'], 400);
        return;
    }
    $groupName = $data['name'];

    // Obtener el usuario desde la cookie JWT
    $jwt = $_COOKIE['auth'] ?? null;
    $decoded = JWTHandler::decode($jwt);

    if (!$decoded || !isset($decoded['data'])) {
        Flight::json(["message" => "Token inválido o expirado."], 401);
        return;
    }

    $userData = (array) $decoded["data"];
    $usuarioActualId = $userData["id"] ?? null;

    // Obtener el email del usuario autenticado
    $stmt = $pdo->prepare("SELECT email FROM usuarios WHERE id = ?");
    $stmt->execute([$usuarioActualId]);
    $usuarioActual = $stmt->fetch(PDO::FETCH_ASSOC);
    $usuarioActualEmail = $usuarioActual['email'] ?? null;

    if (!$usuarioActualEmail) {
        Flight::json(['error' => 'No se pudo obtener el correo del usuario'], 500);
        return;
    }

    // Buscar el grupo por nombre
    $stmt = $pdo->prepare("SELECT id FROM grupos WHERE nombre = ?");
    $stmt->execute([$groupName]);
    $grupo = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$grupo) {
        Flight::json(['error' => 'Grupo no encontrado'], 404);
        return;
    }

    $grupoId = $grupo['id'];

    // Obtener los correos asociados al grupo
    $stmt = $pdo->prepare("
        SELECT u.email FROM usuarios_grupos ug
        JOIN usuarios u ON ug.usuario = u.id
        WHERE ug.grupo = ?
    ");
    $stmt->execute([$grupoId]);
    $emails = $stmt->fetchAll(PDO::FETCH_COLUMN);

    // Verificar si el email del usuario está en la lista
    if (!in_array($usuarioActualEmail, $emails)) {
        Flight::json(['error' => 'No tienes permiso para eliminar este grupo'], 403);
        return;
    }

    // Eliminar asociaciones de usuarios con el grupo
    $stmt = $pdo->prepare("DELETE FROM usuarios_grupos WHERE grupo = ?");
    $stmt->execute([$grupoId]);

    // Eliminar el grupo
    $stmt = $pdo->prepare("DELETE FROM grupos WHERE id = ?");
    $stmt->execute([$grupoId]);

    Flight::json(['message' => 'Grupo y asociaciones eliminados correctamente'], 200);
});

Flight::start();
?>