CREATE DATABASE IF NOT EXISTS cloudblock_db
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE cloudblock_db;

SET NAMES utf8mb4;

-- Tabla de usuarios
CREATE TABLE usuarios (
    id VARCHAR(32) PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    apellidos VARCHAR(40) NOT NULL,
    email VARCHAR(40) UNIQUE NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CHECK (email REGEXP '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
) ENGINE=InnoDB;

-- Tabla de directorios (auto-referenciada)
CREATE TABLE directorios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    ruta_padre INT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (ruta_padre) REFERENCES directorios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Tabla de archivos
CREATE TABLE archivos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    tamano INT NOT NULL,
    ruta INT NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    favorito BOOLEAN DEFAULT false NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (ruta) REFERENCES directorios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Historial de contraseñas
CREATE TABLE historial_pass (
    id INT AUTO_INCREMENT PRIMARY KEY,
    password_hash VARCHAR(100) NOT NULL,
    tipo VARCHAR(13) NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    estado VARCHAR(13) DEFAULT 'activa' NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    CHECK (tipo IN ('inicial', 'recuperacion')),
    CHECK (estado IN ('activa', 'deshabilitada'))
) ENGINE=InnoDB;

-- Almacenamiento de usuarios
CREATE TABLE almacenamiento (
    propietario VARCHAR(32) PRIMARY KEY,
    almacenamiento_maximo BIGINT UNSIGNED NOT NULL,
    almacenamiento_actual BIGINT UNSIGNED NOT NULL,
    tamano_alerta BIGINT UNSIGNED NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Tokens de autenticación
CREATE TABLE token (
    token VARCHAR(100) PRIMARY KEY,
    fecha_validacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ultima_fecha TIMESTAMP NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    ip_origen VARCHAR(15) NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    CHECK (ip_origen REGEXP '^([0-9]{1,3}\\.){3}[0-9]{1,3}$')
) ENGINE=InnoDB;

-- Registro de conexiones
CREATE TABLE registro_conexiones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_origen VARCHAR(15) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    estado VARCHAR(7) DEFAULT 'exitoso' NOT NULL,
    navegador VARCHAR(100) NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    CHECK (estado IN ('exitoso', 'fallido')),
    CHECK (ip_origen REGEXP '^([0-9]{1,3}\\.){3}[0-9]{1,3}$')
) ENGINE=InnoDB;

-- Grupos de usuarios
CREATE TABLE grupos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    descripcion TEXT NOT NULL
) ENGINE=InnoDB;

-- Relación usuarios-grupos
CREATE TABLE usuarios_grupos (
    usuario VARCHAR(32),
    grupo INT,
    PRIMARY KEY (usuario, grupo),
    FOREIGN KEY (usuario) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (grupo) REFERENCES grupos(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Compartición de recursos
CREATE TABLE comparticion (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fecha_comparticion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    permiso VARCHAR(13) DEFAULT 'lector' NOT NULL,
    estado VARCHAR(8) DEFAULT 'activo' NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    archivo INT NULL,
    directorio INT NULL,
    usuario_destinatario VARCHAR(32) NULL,
    grupo_destinatario INT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (archivo) REFERENCES archivos(id) ON DELETE CASCADE,
    FOREIGN KEY (directorio) REFERENCES directorios(id) ON DELETE CASCADE,
    FOREIGN KEY (usuario_destinatario) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (grupo_destinatario) REFERENCES grupos(id) ON DELETE CASCADE,
    CHECK (permiso IN ('lector', 'copropietario')),
    CHECK (estado IN ('activo', 'revocado')),
    CHECK (
        (archivo IS NOT NULL AND directorio IS NULL) OR
        (archivo IS NULL AND directorio IS NOT NULL)
    ),
    CHECK (
        (usuario_destinatario IS NOT NULL AND grupo_destinatario IS NULL) OR
        (usuario_destinatario IS NULL AND grupo_destinatario IS NOT NULL)
    )
) ENGINE=InnoDB;

-- Notificaciones del sistema
CREATE TABLE notificaciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo VARCHAR(11) NOT NULL,
    mensaje TEXT NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    fecha_lectura TIMESTAMP NULL,
    comparticion INT NULL,
    propietario VARCHAR(32) NOT NULL,
    leida BOOLEAN DEFAULT false NOT NULL,
    FOREIGN KEY (comparticion) REFERENCES comparticion(id) ON DELETE SET NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id) ON DELETE CASCADE,
    CHECK (tipo IN ('seguridad', 'informacion'))
) ENGINE=InnoDB;