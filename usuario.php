<?php
// usuario.php
require_once 'config/config.php';
require_once 'config/jwt.php';

class Usuario {
    private $db;

    public function __construct($pdo) {
        $this->db = $pdo;
    }

    // Registrar un nuevo usuario
    public function registrar($nombre, $email, $password) {
        // Encriptar la contraseña
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        // Insertar el usuario en la base de datos
        $sql = "INSERT INTO usuarios (nombre, email, password) VALUES (:nombre, :email, :password)";
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':nombre', $nombre);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $passwordHash);

        if ($stmt->execute()) {
            // Generar el JWT para el usuario después de que se haya registrado
            $userData = ['nombre' => $nombre, 'email' => $email];
            $token = JWTHandler::encode($userData);
            return $token;
        }

        return null;
    }

    // Validar el token JWT
    public function validarToken($token) {
        $decoded = JWTHandler::decode($token);
        if ($decoded) {
            return $decoded;
        }
        return null;
    }
}
?>
