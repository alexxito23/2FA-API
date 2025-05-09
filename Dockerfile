FROM php:8.2-fpm

# Instala dependencias del sistema
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libzip-dev \
    && docker-php-ext-install zip pdo pdo_mysql

# Configura el directorio de trabajo
WORKDIR /var/www/html

# Copia los archivos de composer primero
COPY composer.json composer.lock ./

# Instala Composer y las dependencias
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && composer install --no-dev --no-scripts --no-autoloader

# Copia el resto de la aplicación
COPY . .

# Genera el autoloader
RUN composer dump-autoload --optimize

# Ajusta permisos
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Puerto expuesto (para PHP-FPM)
EXPOSE 9000

# Comando para iniciar PHP-FPM
CMD ["php-fpm"]