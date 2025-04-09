<?php

use Symfony\Component\Cache\Adapter\FilesystemAdapter;

require './vendor/autoload.php';

// Crear un adaptador de cache basado en archivos
$cache = new FilesystemAdapter();

// Crear un objeto CacheItem para un elemento en particular
$item = $cache->getItem('mi_cache_item');

// Establecer que el item expire después de 10 segundos
$item->expiresAfter(10); // 10 segundos de expiración para pruebas rápidas

// Verificar si el elemento ya está en cache
if (!$item->isHit()) {
    // Si no existe en el cache, agregar el array
    $array = ['nombre' => 'Juan', 'edad' => 30, 'ocupacion' => 'Desarrollador'];
    
    // Guardar el array en cache
    $item->set($array);
    // Guardar el elemento en cache
    $cache->save($item);
    echo "Array guardado en cache.\n";
} else {
    echo "Array ya estaba en cache: \n";
    print_r($item->get()); // Imprimir el array que fue recuperado del cache
}

?>
