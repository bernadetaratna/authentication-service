CREATE TABLE user_roles (
    user_role_id        VARCHAR(36),
    role_id             VARCHAR(36)     NOT NULL,
    user_id             VARCHAR(36)     NOT NULL,
    is_active           BOOLEAN         NOT NULL    DEFAULT TRUE,
    is_deleted          BOOLEAN         NOT NULL    DEFAULT FALSE,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint userroles_pk primary key (user_role_id),
    constraint userroles_user_roles unique (user_id, role_id)
)