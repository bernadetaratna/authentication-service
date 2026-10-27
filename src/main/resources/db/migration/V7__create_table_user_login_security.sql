CREATE TABLE user_login_security (
    user_login_id       VARCHAR(36),
    user_id             VARCHAR(36)     NOT NULL,
    device_id           VARCHAR(100)    NOT NULL,
    failed_attempts     INTEGER         NOT NULL    DEFAULT 0,
    started_time        TIMESTAMP,
    locked_until        TIMESTAMP,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint uq_user_login_security_user_device UNIQUE (user_id, device_id)
)
