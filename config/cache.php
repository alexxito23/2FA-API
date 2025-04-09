<?php
require_once '../vendor/autoload.php'; 

use Symfony\Component\Cache\Adapter\FilesystemAdapter;
$cache = new FilesystemAdapter();

return $cache;
?>