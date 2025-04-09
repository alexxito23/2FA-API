<?php

function cleanupCache() {
    $cacheDir = '../auth/';
    $currentTime = time();
    $expirationTime = 420; // 7 minutos = 420 segundos

    // Obtener todos los archivos en la carpeta de caché
    $files = scandir($cacheDir);

/*     foreach ($files as $file) {
        // Ignorar directorios y archivos ocultos
        if ($file == '.' || $file == '..') {
            continue;
        }

        $filePath = $cacheDir . $file;
        
        if (file_exists($filePath)) {
            // Leer el archivo encriptado
            $encryptedContent = file_get_contents($filePath);

            // Verificar que el archivo tiene suficiente contenido para tener IV (16 bytes) + datos encriptados
            if (strlen($encryptedContent) < 16) {
                continue; // Si el archivo no es lo suficientemente grande, lo saltamos
            }

            // Obtener el IV del archivo encriptado (los primeros 16 bytes)
            $iv = substr($encryptedContent, 0, 16);
            $encryptedData = substr($encryptedContent, 16); // El resto es el contenido encriptado

            // Desencriptar el contenido
            $secretKey = 'mi_clave_secreta'; // La misma clave secreta usada para la encriptación
            $decryptedData = openssl_decrypt($encryptedData, 'aes-256-cbc', $secretKey, 0, $iv);

            if ($decryptedData === false) {
                // Si hay un error al desencriptar, se ignora este archivo
                continue;
            }

            // Convertir los datos desencriptados a un array
            $cacheData = json_decode($decryptedData, true);

            if ($cacheData === null) {
                // Si no se pudo convertir a JSON, continuar con el siguiente archivo
                continue;
            }

            // Verificar si el timestamp está presente en los datos desencriptados
            if (isset($cacheData['timestamp'])) {
                // Verificar si el archivo ha expirado
                if ($currentTime - $cacheData['timestamp'] > $expirationTime) {
                    // Eliminar el archivo si ha expirado
                    unlink($filePath);
                }
            }
        }
    } */
}


?>