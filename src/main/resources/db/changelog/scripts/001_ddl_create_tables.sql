create table users (
    id serial primary key,
    username varchar(20) NOT NULL UNIQUE,
    password varchar(120) NOT NULL
);

create table roles (
    id serial primary key,
    name varchar(20) NOT NULL UNIQUE
);

create table users_roles (
    role_id int references roles(id),
    user_id int references users(id)
)