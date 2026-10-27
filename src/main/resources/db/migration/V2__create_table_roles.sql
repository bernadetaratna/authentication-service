CREATE TABLE roles (
    role_id             VARCHAR(36),
    role_name           VARCHAR(100)    NOT NULL    UNIQUE,
    is_active           BOOLEAN         NOT NULL    DEFAULT TRUE,
    is_deleted          BOOLEAN         NOT NULL    DEFAULT FALSE,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint roles_pk primary key (role_id)
)