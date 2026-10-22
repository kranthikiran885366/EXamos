BEGIN;

CREATE TABLE examos_agent_heartbeat_records (
    heartbeat_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id varchar(63) NOT NULL REFERENCES examos_devices(device_id) ON DELETE CASCADE,
    reported_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    payload jsonb NOT NULL,
    UNIQUE (device_id, reported_at),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload->>'device_id' = device_id),
    CHECK (jsonb_typeof(payload->'timestamp') = 'number' AND (payload->>'timestamp') ~ '^[0-9]{1,12}$'),
    CHECK (jsonb_typeof(payload->'uptime') = 'number' AND (payload->>'uptime') ~ '^[0-9]{1,12}$'),
    CHECK (jsonb_typeof(payload->'cpu_load') = 'number' AND (payload->>'cpu_load')::numeric >= 0),
    CHECK (jsonb_typeof(payload->'mem_total_kb') = 'number' AND (payload->>'mem_total_kb') ~ '^[0-9]{1,15}$'),
    CHECK (jsonb_typeof(payload->'mem_avail_kb') = 'number' AND (payload->>'mem_avail_kb') ~ '^[0-9]{1,15}$'),
    CHECK ((payload->>'mem_avail_kb')::numeric <= (payload->>'mem_total_kb')::numeric),
    CHECK (jsonb_typeof(payload->'process_count') = 'number' AND (payload->>'process_count') ~ '^[0-9]{1,9}$'),
    CHECK (jsonb_typeof(payload->'hardware') = 'object'),
    CHECK (jsonb_typeof(payload->'rf_environment') = 'object')
);

CREATE INDEX examos_agent_heartbeat_device_time_idx
    ON examos_agent_heartbeat_records (device_id, reported_at DESC);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 6);

COMMIT;
