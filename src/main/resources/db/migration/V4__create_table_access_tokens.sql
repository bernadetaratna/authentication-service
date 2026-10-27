CREATE TABLE access_tokens (
    access_token_id     VARCHAR(36),
    user_id             VARCHAR(36)     NOT NULL,
    jti                 VARCHAR(255)    NOT NULL,
    expired_time        TIMESTAMP       NOT NULL,
    revoked_time        TIMESTAMP,
    session_id          VARCHAR(36)     NOT NULL,
    created_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_time        TIMESTAMP       NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    constraint accesstokens_pk primary key (access_token_id)
)