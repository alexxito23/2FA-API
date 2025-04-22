CREATE TABLE usuarios (
    id VARCHAR(32) PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    apellidos VARCHAR(40) NOT NULL,
    email VARCHAR(40) UNIQUE NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  	CHECK (email REGEXP '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE TABLE directorios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  	propietario VARCHAR(32) NOT NULL,
    ruta_padre INT NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id),
    FOREIGN KEY (ruta_padre) REFERENCES directorios(id)
);

CREATE TABLE archivos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
  	fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  	tamaño INT NOT NULL,
  	ruta INT NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    favorito BOOLEAN DEFAULT false NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id),
    FOREIGN KEY (ruta) REFERENCES directorios(id)
);

CREATE TABLE historial_pass (
    id INT AUTO_INCREMENT PRIMARY KEY,
  	password_hash VARCHAR(100) NOT NULL,
  	tipo VARCHAR(13) NOT NULL,
    propietario VARCHAR(32) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    estado VARCHAR(13) DEFAULT 'activa' NOT NULL,
    FOREIGN KEY (propietario) REFERENCES usuarios(id),
  	CHECK (tipo IN ('inicial', 'recuperacion')),
    CHECK (estado IN ('activa', 'deshabilitada'))
);

CREATE TABLE almacenamiento (
    propietario VARCHAR(32),
    almacenamiento_maximo INT NOT NULL,
    almacenamiento_actual INT NOT NULL,
  	tamaño_alerta INT NOT NULL,
  	PRIMARY KEY (propietario),
    FOREIGN KEY (propietario) REFERENCES usuarios(id)
);

CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evento VARCHAR(11) NOT NULL,
    descripcion TEXT NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  	ip_origen VARCHAR(15) NOT NULL,
    estado VARCHAR(7) DEFAULT 'exitoso' NOT NULL,
  	propietario VARCHAR(32) NOT NULL,
  	archivo INT NULL,
  	CHECK (evento IN ('error', 'informacion', 'advertencia', 'seguridad', 'otro')),
  	CHECK (ip_origen REGEXP '^([0-9]{1,3}\.){3}[0-9]{1,3}$'),
  	CHECK (estado IN ('exitoso', 'fallido')),
  	FOREIGN KEY (propietario) REFERENCES usuarios(id),
  	FOREIGN key (archivo) REFERENCES archivos(id)
);

CREATE TABLE token (
    token VARCHAR(100) PRIMARY KEY,
    fecha_validacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    fecha_expiracion TIMESTAMP NOT NULL,
    propietario VARCHAR(32) NOT NULL,
  	ip_origen VARCHAR(15) NOT NULL,
  	CHECK (ip_origen REGEXP '^([0-9]{1,3}\.){3}[0-9]{1,3}$'),
    FOREIGN KEY (propietario) REFERENCES usuarios(id)
);

CREATE TABLE registro_conexiones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_origen VARCHAR(15) NOT NULL,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  	fecha_ultima_conexion TIMESTAMP NULL,
  	estado VARCHAR(7) DEFAULT 'exitoso' NOT NULL,
	  navegador VARCHAR(100) NOT NULL,
  	propietario VARCHAR(32) NOT NULL,
  	CHECK (estado IN ('exitoso', 'fallido')),
  	CHECK (ip_origen REGEXP '^([0-9]{1,3}\.){3}[0-9]{1,3}$'),
    FOREIGN KEY (propietario) REFERENCES usuarios(id)
);

CREATE TABLE grupos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(40) NOT NULL,
    descripcion TEXT NOT NULL
);

CREATE TABLE usuarios_grupos (
    usuario VARCHAR(32),
    grupo INT,
  	PRIMARY KEY (usuario, grupo),
    FOREIGN KEY (usuario) REFERENCES usuarios(id),
    FOREIGN KEY (grupo) REFERENCES grupos(id)
);

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
  	CHECK (permiso IN ('lector', 'copropietario')),
    CHECK (estado in ('activo', 'revocado')),
    CHECK (
        (archivo IS NOT NULL AND directorio IS NULL) OR
        (archivo IS NULL AND directorio IS NOT NULL)
    ),
    CHECK (
        (usuario_destinatario IS NOT NULL AND grupo_destinatario IS NULL) OR
        (usuario_destinatario IS NULL AND grupo_destinatario IS NOT NULL)
    ),
    FOREIGN KEY (propietario) REFERENCES usuarios(id),
  	FOREIGN KEY (archivo) REFERENCES archivos(id),
  	FOREIGN KEY (directorio) REFERENCES directorios(id),
  	FOREIGN KEY (usuario_destinatario) REFERENCES usuarios(id),
    FOREIGN KEY (grupo_destinatario) REFERENCES grupos(id)
);

CREATE TABLE notificaciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo VARCHAR(11) NOT NULL,
    mensaje TEXT NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    fecha_lectura TIMESTAMP NULL,
    evento INT NULL,
  	comparticion INT NULL,
    propietario VARCHAR(32) NOT NULL,
    leida BOOLEAN DEFAULT false NOT NULL,
	  CHECK (tipo IN ('seguridad', 'informacion', 'advertencia', 'sistema', 'actividad')),
    CHECK (
        (evento IS NOT NULL AND comparticion IS NULL) OR
        (evento IS NULL AND comparticion IS NOT NULL)
    ),
    FOREIGN KEY (evento) REFERENCES logs(id),
  	FOREIGN KEY (comparticion) REFERENCES comparticion(id),
  	FOREIGN KEY (propietario) REFERENCES usuarios(id)
);
