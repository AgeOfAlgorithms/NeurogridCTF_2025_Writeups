\set ON_ERROR_STOP on

-- 0) Ensure database exists, then connect to it
SELECT 'CREATE DATABASE shugo_system_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'shugo_system_db')
\gexec

\connect shugo_system_db

-- 1) Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2) USERS
CREATE TABLE IF NOT EXISTS public.users (
  id              BIGSERIAL PRIMARY KEY,
  email           VARCHAR(255) NOT NULL,
  password_digest TEXT         NOT NULL,
  role            VARCHAR(16)  NOT NULL DEFAULT 'user',
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Case-insensitive unique email
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname='public' AND indexname='idx_users_email_ci'
  ) THEN
    EXECUTE 'CREATE UNIQUE INDEX idx_users_email_ci ON public.users ((lower(email)))';
  END IF;
END $$;

-- 3) TICKETS
CREATE TABLE IF NOT EXISTS public.tickets (
  id              BIGSERIAL PRIMARY KEY,
  name            VARCHAR(255) NOT NULL,
  bus_code        VARCHAR(64)  NOT NULL,
  start_node      INTEGER      NOT NULL,
  end_node        INTEGER      NOT NULL,
  current_node    INTEGER,
  travel_date     DATE         NOT NULL,
  seats           INTEGER      NOT NULL DEFAULT 1,
  metadata        JSONB,
  user_id         BIGINT REFERENCES public.users(id) ON DELETE SET NULL,

  base_cents      INTEGER      NOT NULL DEFAULT 0,
  penalty_cents   INTEGER      NOT NULL DEFAULT 0,
  total_cents     INTEGER      NOT NULL DEFAULT 0,
  distance_edges  INTEGER      NOT NULL DEFAULT 0,

  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS index_tickets_on_bus_code ON public.tickets (bus_code);
CREATE INDEX IF NOT EXISTS index_tickets_on_user_id  ON public.tickets (user_id);

-- Unique ticket names
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname='public' AND indexname='index_tickets_on_name'
  ) THEN
    EXECUTE 'CREATE UNIQUE INDEX index_tickets_on_name ON public.tickets (name)';
  END IF;
END $$;

-- 4) LOGIC BUS TRACKER TABLES
-- Current bus state (one row per bus)
CREATE TABLE IF NOT EXISTS public.logic_buses (
  id            BIGSERIAL PRIMARY KEY,
  code          VARCHAR(32)  NOT NULL,               -- stable bus code (e.g. "0", "1", ...)
  start_id      INTEGER      NOT NULL,               -- grid node id (internal id space)
  end_id        INTEGER      NOT NULL,
  path_ids      JSONB        NOT NULL DEFAULT '[]',  -- array of node ids, e.g. [0,1,2,...]
  cur_index     DOUBLE PRECISION NOT NULL DEFAULT 0, -- fractional index along path
  speed         DOUBLE PRECISION NOT NULL DEFAULT 1, -- nodes per tick (tick = 10s by default)
  paused_until  TIMESTAMPTZ,                         -- dwell end time if pausing at stop/end
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Ensure unique bus codes
CREATE UNIQUE INDEX IF NOT EXISTS index_logic_buses_on_code ON public.logic_buses (code);

-- Useful partial indexes
CREATE INDEX IF NOT EXISTS index_logic_buses_on_paused_until
  ON public.logic_buses (paused_until)
  WHERE paused_until IS NOT NULL;

-- Historical positions (append-only, one row per tick per bus)
CREATE TABLE IF NOT EXISTS public.logic_bus_points (
  id         BIGSERIAL PRIMARY KEY,
  bus_id     BIGINT       NOT NULL REFERENCES public.logic_buses(id) ON DELETE CASCADE,
  at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),   -- observation time
  node_id    INTEGER      NOT NULL,                 -- grid node id at that instant
  meta       JSONB        NOT NULL DEFAULT '{}'     -- e.g. {"speed":1.2,"start_id":0,"end_id":95}
);

-- Time-series & lookup helpers
CREATE INDEX IF NOT EXISTS index_logic_bus_points_on_bus_at
  ON public.logic_bus_points (bus_id, at DESC);

CREATE INDEX IF NOT EXISTS index_logic_bus_points_on_at
  ON public.logic_bus_points (at DESC);

-- GIN on meta for ad-hoc queries
CREATE INDEX IF NOT EXISTS index_logic_bus_points_on_meta
  ON public.logic_bus_points USING GIN (meta);

-- Keep updated_at fresh on UPDATEs (matches style of your schema)
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_logic_buses_set_updated_at'
  ) THEN
    CREATE TRIGGER trg_logic_buses_set_updated_at
      BEFORE UPDATE ON public.logic_buses
      FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
  END IF;
END $$;

-- 5) SEEDS (pure SQL; no DO, so psql variable works)
\set seed_password 'SuperSecureAdminPassword'

-- Admin
INSERT INTO public.users(email,password_digest,role)
SELECT 'admin@shugo', crypt(:'seed_password', gen_salt('bf', 12)), 'admin'
WHERE NOT EXISTS (SELECT 1 FROM public.users WHERE lower(email)='admin@shugo');

-- Users
INSERT INTO public.users(email,password_digest,role)
SELECT 'user1@shugo', crypt(:'seed_password', gen_salt('bf', 12)), 'user'
WHERE NOT EXISTS (SELECT 1 FROM public.users WHERE lower(email)='user1@shugo');

INSERT INTO public.users(email,password_digest,role)
SELECT 'user2@shugo', crypt(:'seed_password', gen_salt('bf', 12)), 'user'
WHERE NOT EXISTS (SELECT 1 FROM public.users WHERE lower(email)='user2@shugo');

INSERT INTO public.users(email,password_digest,role)
SELECT 'user3@shugo', crypt(:'seed_password', gen_salt('bf', 12)), 'user'
WHERE NOT EXISTS (SELECT 1 FROM public.users WHERE lower(email)='user3@shugo');



-- 6) TICKET SEEDS FOR ADMIN
-- Create a handful of mock tickets for the admin user.
WITH admin_user AS (
  SELECT id
  FROM public.users
  WHERE lower(email) = 'admin@shugo'
  LIMIT 1
)
INSERT INTO public.tickets (
  name,
  bus_code,
  start_node,
  end_node,
  current_node,
  travel_date,
  seats,
  metadata,
  user_id,
  base_cents,
  penalty_cents,
  total_cents,
  distance_edges
)
SELECT
  format('ADM-SEED-%s', gs)                      AS name,
  format('BUS-%s', ((gs - 1) % 5) + 1)             AS bus_code,
  ((gs - 1) * 3) % 30                              AS start_node,
  (((gs - 1) * 3) % 30) + 10 + ((gs - 1) % 5)      AS end_node,
  ((gs - 1) * 3) % 30                              AS current_node,
  CURRENT_DATE + ((gs - 1) % 7)                    AS travel_date,
  1 + ((gs - 1) % 3)                               AS seats,
  jsonb_build_object(
    'seed', true,
    'note', 'admin seed ticket',
    'index', gs
  )                                               AS metadata,
  admin_user.id                                   AS user_id,
  (ABS(
    ((((gs - 1) * 3) % 30) + 10 + ((gs - 1) % 5))
    - (((gs - 1) * 3) % 30)
  )) * 5000                                        AS base_cents,
  0                                                AS penalty_cents,
  (ABS(
    ((((gs - 1) * 3) % 30) + 10 + ((gs - 1) % 5))
    - (((gs - 1) * 3) % 30)
  )) * 5000                                        AS total_cents,
  ABS(
    ((((gs - 1) * 3) % 30) + 10 + ((gs - 1) % 5))
    - (((gs - 1) * 3) % 30)
  )                                                AS distance_edges
FROM generate_series(1, 10) AS gs
CROSS JOIN admin_user
WHERE admin_user.id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM public.tickets t
    WHERE t.user_id = admin_user.id
      AND t.name LIKE 'ADM-SEED-%'
  );
