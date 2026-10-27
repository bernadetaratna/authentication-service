CREATE TABLE user_sessions (
    session_id          VARCHAR(36),
    user_id             VARCHAR(36)     NOT NULL,
    device_id           VARCHAR(255)    NOT NULL,
    is_active           BOOLEAN         NOT NULL    DEFAULT TRUE,
    revoked_time        TIMESTAMP,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint usersessions_pk primary key (session_id)
);

CREATE UNIQUE INDEX uq_user_sessions_active_user
    ON user_sessions (user_id)
    WHERE is_active = TRUE;