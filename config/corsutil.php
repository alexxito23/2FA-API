<?php

namespace api\config;

class CorsUtil
{
    public function set(array $params): void
    {
        $solicitud = Flight::request();
        $respuesta = Flight::response();
        if ($request->getVar('HTTP_ORIGIN') !== '') {
            $this->allowOrigins();
            $response->header('Access-Control-Allow-Credentials', 'true');
            $response->header('Access-Control-Max-Age', '86400');
        }

        if ($request->method === 'OPTIONS') {
            if ($request->getVar('HTTP_ACCESS_CONTROL_REQUEST_METHOD') !== '') {
                $response->header(
                    'Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD'
                );
            }
            if ($request->getVar('HTTP_ACCESS_CONTROL_REQUEST_HEADERS') !== '') {
                $response->header(
                    "Access-Control-Allow-Headers",
                    $request->getVar('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
                );
            }

            $response->status(200);
            $response->send();
            exit;
        }
    }

    private function allowOrigins(): void
    {
        // personaliza tus hosts permitidos aquí.
        $permitidos = [
            'capacitor://localhost',
            'ionic://localhost',
            'http://localhost',
            'http://localhost:4200',
            'http://localhost:8080',
            'http://localhost:8100',
        ];

        $solicitud = Flight::request();

        if (in_array($request->getVar('HTTP_ORIGIN'), $permitidos, true) === true) {
            $respuesta = Flight::response();
            $respuesta->header("Access-Control-Allow-Origin", $request->getVar('HTTP_ORIGIN'));
        }
    }
}

// index.php o donde tengas tus rutas
$CorsUtil = new CorsUtil();

// Esto debe ejecutarse antes de que start se ejecute.
Flight::before('start', [ $CorsUtil, 'setupCors' ]);

?>