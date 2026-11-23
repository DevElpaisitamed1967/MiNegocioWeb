-- Esquema de la base de datos de minegocioweb
-- Motor: MySQL 8.0.16+ | Codificación: utf8mb4
-- Las fechas de autenticación (DATETIME) se guardan siempre en UTC.

CREATE DATABASE IF NOT EXISTS minegocioweb
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE minegocioweb;

-- =====================================================================
-- AUTENTICACIÓN Y AUTORIZACIÓN
-- =====================================================================

-- Roles del sistema. requiere_2fa = 1 obliga a la verificación en dos pasos.
CREATE TABLE IF NOT EXISTS roles (
    id           TINYINT UNSIGNED PRIMARY KEY,
    nombre       VARCHAR(30) NOT NULL UNIQUE,
    requiere_2fa TINYINT(1)  NOT NULL DEFAULT 0
) ENGINE=InnoDB;

INSERT IGNORE INTO roles (id, nombre, requiere_2fa) VALUES
    (1, 'Administrador', 1),
    (2, 'Asistente',     1),
    (3, 'Colaborador',   1),
    (4, 'Consultor',     0);

-- Usuarios. password_hash es NULL en cuentas creadas solo con Google/Microsoft.
CREATE TABLE IF NOT EXISTS usuarios (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    nombre               VARCHAR(100) NOT NULL,
    email                VARCHAR(254) NOT NULL UNIQUE,
    password_hash        VARCHAR(255) NULL,
    email_verificado     TINYINT(1)   NOT NULL DEFAULT 0,
    activo               TINYINT(1)   NOT NULL DEFAULT 1,
    intentos_fallidos    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    bloqueado_hasta      DATETIME     NULL,
    totp_secreto_cifrado VARBINARY(255) NULL,
    totp_confirmado      TINYINT(1)   NOT NULL DEFAULT 0,
    totp_ultimo_paso     BIGINT UNSIGNED NULL,
    ultimo_login         DATETIME     NULL,
    creado_en            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Un usuario puede tener varios roles; al iniciar sesión elige con cuál entra.
CREATE TABLE IF NOT EXISTS usuario_roles (
    usuario_id INT UNSIGNED     NOT NULL,
    rol_id     TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY (usuario_id, rol_id),
    CONSTRAINT fk_ur_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_rol     FOREIGN KEY (rol_id)     REFERENCES roles(id)    ON DELETE RESTRICT
) ENGINE=InnoDB;

-- Códigos de respaldo del 2FA (solo se guarda el hash SHA-256, un solo uso).
CREATE TABLE IF NOT EXISTS codigos_respaldo (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    usuario_id  INT UNSIGNED NOT NULL,
    codigo_hash CHAR(64)     NOT NULL,
    usado_en    DATETIME     NULL,
    INDEX idx_cr_usuario (usuario_id, codigo_hash),
    CONSTRAINT fk_cr_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Identidades externas (Google, Microsoft/Outlook) vinculadas a un usuario.
CREATE TABLE IF NOT EXISTS identidades_oauth (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT UNSIGNED NOT NULL,
    proveedor  VARCHAR(30)  NOT NULL,
    sujeto     VARCHAR(190) NOT NULL,
    email      VARCHAR(254) NULL,
    creado_en  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_identidad (proveedor, sujeto),
    CONSTRAINT fk_io_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Enlaces y códigos de un solo uso (verificar correo, enrolar 2FA, recuperar contraseña). Solo hashes.
CREATE TABLE IF NOT EXISTS tokens_email (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT UNSIGNED NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    tipo       ENUM('verificar_email', 'enrolar_2fa', 'recuperar_password') NOT NULL,
    expira_en  DATETIME     NOT NULL,
    usado_en   DATETIME     NULL,
    INDEX idx_te_hash (token_hash),
    CONSTRAINT fk_te_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Sesiones en el servidor (revocables). id = SHA-256 del identificador de la cookie.
CREATE TABLE IF NOT EXISTS sesiones (
    id            CHAR(64)         PRIMARY KEY,
    usuario_id    INT UNSIGNED     NOT NULL,
    rol_id        TINYINT UNSIGNED NOT NULL,
    creado_en     DATETIME         NOT NULL,
    ultimo_acceso DATETIME         NOT NULL,
    expira_en     DATETIME         NOT NULL,
    revocada      TINYINT(1)       NOT NULL DEFAULT 0,
    ip            VARCHAR(45)      NULL,
    user_agent    VARCHAR(255)     NULL,
    INDEX idx_ses_usuario (usuario_id),
    CONSTRAINT fk_ses_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    CONSTRAINT fk_ses_rol     FOREIGN KEY (rol_id)     REFERENCES roles(id)    ON DELETE RESTRICT
) ENGINE=InnoDB;

-- Bitácora de eventos de autenticación.
CREATE TABLE IF NOT EXISTS auditoria_auth (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT UNSIGNED NULL,
    email      VARCHAR(254) NULL,
    evento     VARCHAR(50)  NOT NULL,
    exito      TINYINT(1)   NOT NULL,
    ip         VARCHAR(45)  NULL,
    detalle    VARCHAR(255) NULL,
    creado_en  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_aud_usuario (usuario_id),
    INDEX idx_aud_evento (evento, creado_en)
) ENGINE=InnoDB;

-- =====================================================================
-- NEGOCIO
-- =====================================================================

CREATE TABLE IF NOT EXISTS clientes (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    nombre     VARCHAR(120) NOT NULL,
    email      VARCHAR(150) UNIQUE,
    telefono   VARCHAR(30),
    direccion  VARCHAR(255),
    creado_en  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS categorias (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    nombre      VARCHAR(100) NOT NULL UNIQUE,
    descripcion VARCHAR(255)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS productos (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    categoria_id INT UNSIGNED NULL,
    nombre       VARCHAR(150)   NOT NULL,
    descripcion  TEXT,
    precio       DECIMAL(12,2)  NOT NULL CHECK (precio >= 0),
    stock        INT UNSIGNED   NOT NULL DEFAULT 0,
    activo       TINYINT(1)     NOT NULL DEFAULT 1,
    creado_en    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_productos_categoria
        FOREIGN KEY (categoria_id) REFERENCES categorias(id)
        ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_productos_nombre (nombre)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pedidos (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    cliente_id INT UNSIGNED NOT NULL,
    usuario_id INT UNSIGNED NULL,
    estado     ENUM('pendiente', 'pagado', 'enviado', 'entregado', 'cancelado')
               NOT NULL DEFAULT 'pendiente',
    total      DECIMAL(12,2) NOT NULL DEFAULT 0,
    creado_en  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pedidos_cliente
        FOREIGN KEY (cliente_id) REFERENCES clientes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_pedidos_usuario
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        ON UPDATE CASCADE ON DELETE SET NULL,
    INDEX idx_pedidos_estado (estado)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS detalle_pedidos (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    pedido_id       INT UNSIGNED  NOT NULL,
    producto_id     INT UNSIGNED  NOT NULL,
    cantidad        INT UNSIGNED  NOT NULL CHECK (cantidad > 0),
    precio_unitario DECIMAL(12,2) NOT NULL CHECK (precio_unitario >= 0),
    CONSTRAINT fk_detalle_pedido
        FOREIGN KEY (pedido_id) REFERENCES pedidos(id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_detalle_producto
        FOREIGN KEY (producto_id) REFERENCES productos(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB;

-- =====================================================================
-- ACTUALIZACIONES PARA BASES YA CREADAS (se pueden ejecutar varias veces)
-- =====================================================================

-- Añade el tipo 'recuperar_password' si la tabla se creó con una versión anterior.
ALTER TABLE tokens_email
    MODIFY tipo ENUM('verificar_email', 'enrolar_2fa', 'recuperar_password') NOT NULL;
