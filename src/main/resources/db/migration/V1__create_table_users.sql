CREATE TABLE users (
    user_id             VARCHAR(36),
    email               VARCHAR(100)    NOT NULL,
    password            VARCHAR(255)    NOT NULL,
    user_name           VARCHAR(50)     NOT NULL,
    full_name           VARCHAR(100)    NOT NULL,
    is_active           BOOLEAN         NOT NULL    DEFAULT TRUE,
    is_deleted          BOOLEAN         NOT NULL    DEFAULT FALSE,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint users_pk primary key (user_id)
);

CREATE UNIQUE INDEX uq_users_email_active
    ON users (LOWER(email))
    WHERE is_deleted = FALSE;

CREATE UNIQUE INDEX uq_users_username_active
    ON users (LOWER(user_name))
    WHERE is_deleted = FALSE;