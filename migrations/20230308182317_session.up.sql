CREATE TABLE session (
    id uuid NOT NULL PRIMARY KEY,
    uid character varying(255) NOT NULL,
    name character varying NOT NULL,
    email character varying NOT NULL,
    groups character varying[],
    expire timestamp with time zone NOT NULL
);

CREATE INDEX session_expire_idx ON session (expire);
