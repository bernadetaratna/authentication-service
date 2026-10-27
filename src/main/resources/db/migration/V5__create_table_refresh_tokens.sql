CREATE TABLE refresh_tokens (
    refresh_token_id    VARCHAR(36),
    user_id             VARCHAR(36)     NOT NULL,
    token               VARCHAR(255)    NOT NULL,
    expired_time        TIMESTAMP       NOT NULL,
    revoked_time        TIMESTAMP,
    session_id          VARCHAR(36)     NOT NULL,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint refreshtokens_pk primary key (refresh_token_id)
)