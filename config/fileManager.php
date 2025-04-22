<?php

class FileManager
{
    private string $basePath = '/var/shared';

    public function createDirectory(string $relativePath): bool|string {
        $fullPath = rtrim($this->basePath, '/') . '/' . trim($relativePath, '/');
        $realBase = realpath($this->basePath);

        $realTarget = realpath(dirname($fullPath));

        if ($realTarget === false || strpos($realTarget, $realBase) !== 0) {
            return false;
        }

        if (file_exists($fullPath)) return false;

        if (!mkdir($fullPath, 0775, true)) {
            return false;
        }

        return true;
    }

    public function deleteDirectory(string $relativePath): bool {
        $fullPath = rtrim($this->basePath, '/') . '/' . trim($relativePath, '/');
        $realPath = realpath($fullPath);
        $baseRealPath = realpath($this->basePath);
    
        if ($realPath === false || !is_dir($realPath)) {
            return false;
        }
    
        if (strpos($realPath, $baseRealPath) !== 0) {
            return false;
        }
    
        $this->deleteContents($realPath);
    
        if (!rmdir($realPath)) {
            return false;
        }
    
        return true;
    }

    public function deleteContents(string $realPath): void {
        // Iterador recursivo para eliminar archivos y subdirectorios
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($realPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
    
        foreach ($files as $fileinfo) {
            $itemRealPath = $fileinfo->getRealPath();
    
            if (strpos($itemRealPath, $realPath) === 0) {
                if ($fileinfo->isDir()) {
                    rmdir($itemRealPath);
                } else {
                    unlink($itemRealPath); 
                }
            }
        }
    }    

    public function scanDirectory($userId) {
        // Construir la ruta del directorio del usuario
        $dirPath = rtrim($this->basePath, '/') . '/' . trim($userId, '/');
    
        // Resolver ruta real y validar que está dentro de basePath
        $realPath = realpath($dirPath);
        $baseRealPath = realpath($this->basePath);
    
        if ($realPath === false || strpos($realPath, $baseRealPath) !== 0) {
            return;
        }
    
        // Verificar que la ruta sea un directorio
        if (!is_dir($realPath)) {
            return;
        }
    
        // Escanear el directorio
        $contents = array_diff(scandir($realPath), ['.', '..']);
    
        // Obtener detalles de cada archivo/directorio
        $fileDetails = [];
        foreach ($contents as $file) {
            $filePath = $realPath . '/' . $file;
    
            if (is_file($filePath)) {
                $fileDetails[] = [
                    'nombre' => $file,
                    'tamano' => $this->formatBytes(filesize($filePath)),
                    'modificacion' => date("Y-m-d H:i:s", filemtime($filePath)),
                    'tipo' => 'Archivo'
                ];
            } elseif (is_dir($filePath)) {
                $fileDetails[] = [
                    'nombre' => $file,
                    'tamano' => 'N/A',
                    'modificacion' => date("Y-m-d H:i:s", filemtime($filePath)),
                    'tipo' => 'Directorio'
                ];
            }
        }
    
        return ["contenido" => $fileDetails];
    }
    
    private function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $bytes /= pow(1024, $pow);
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
    
    public function eliminarFichero(string $relativePath): bool|string {
        $fullPath = rtrim($this->basePath, '/') . '/' . trim($relativePath, '/');
    
        $realPath = realpath($fullPath);
        $baseRealPath = realpath($this->basePath);
    
        if ($realPath === false || strpos($realPath, $baseRealPath) !== 0) {
            return "Ruta inválida o fuera del directorio base.";
        }
    
        if (!file_exists($realPath)) {
            return "El archivo no existe.";
        }
    
        if (!is_file($realPath)) {
            return "No es un archivo válido.";
        }
    
        if (!unlink($realPath)) {
            return "No se pudo eliminar el archivo.";
        }
    
        return true;
    }
}

?>