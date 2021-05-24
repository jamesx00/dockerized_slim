FROM php:7.2.34-apache 
RUN docker-php-ext-install mysqli pdo_mysql
RUN apt-get update \
    && apt-get install -y libzip-dev \
    && apt-get install -y zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install zip
RUN pecl install grpc
RUN apt-get update
RUN apt-get install fish -y
RUN apt-get install libpng-dev zlib1g-dev libicu-dev g++ -y
RUN docker-php-ext-install gd
RUN docker-php-ext-install bcmath
RUN docker-php-ext-configure intl
RUN docker-php-ext-install intl
RUN docker-php-ext-enable grpc
RUN a2enmod rewrite
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
COPY ./www/ /var/www/html