# Smile Migraine LAMP + Slim PHP

Make sure to run below command to clone Smile Migraine's backend api

```
RUN git clone git@github.com:aommy05349/smapi_dev.git www
```

I use docker-compose as an orchestrator. To run these containers:

```
docker-compose up -d
```

Docker Apache, MySql 8.0, PhpMyAdmin and Php

- You can use MariaDB 10.1 if you checkout to the tag `mariadb-10.1` - contribution made by [luca-vercelli](https://github.com/luca-vercelli)
- You can use MySql 5.7 if you checkout to the tag `mysql5.7`

Open phpmyadmin at [http://localhost:8000](http://localhost:8000)
Open web browser to look at a simple php example at [http://localhost:8001](http://localhost:8001)

Run mysql client:

- `docker-compose exec db mysql -u root -p` 

Enjoy !