-- OCEAN Simulator – DuckDB Schema

CREATE TABLE IF NOT EXISTS pois (
    id INTEGER PRIMARY KEY,
    name VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    x DOUBLE,
    y DOUBLE,
    carrying_capacity INTEGER,
    water_access DOUBLE DEFAULT 0.5,
    food_production DOUBLE DEFAULT 0,
    danger_level DOUBLE DEFAULT 0,
    shelter_quality DOUBLE DEFAULT 0.5,
    description TEXT
);

CREATE TABLE IF NOT EXISTS npcs (
    id INTEGER PRIMARY KEY,
    name VARCHAR NOT NULL,
    born_tick INTEGER NOT NULL DEFAULT 0,
    died_tick INTEGER,
    death_cause VARCHAR,
    sex VARCHAR NOT NULL,
    parent_a INTEGER,
    parent_b INTEGER,
    home_poi INTEGER NOT NULL,
    faction VARCHAR,
    role VARCHAR
    -- TRAIT_COLUMNS
);

CREATE TABLE IF NOT EXISTS npc_state (
    npc_id INTEGER NOT NULL,
    tick INTEGER NOT NULL,
    poi_id INTEGER NOT NULL,
    health DOUBLE NOT NULL DEFAULT 1.0,
    calories_stored DOUBLE NOT NULL DEFAULT 14.0,
    valence DOUBLE DEFAULT 0.0,
    arousal DOUBLE DEFAULT 0.3,
    dominance DOUBLE DEFAULT 0.5,
    status DOUBLE DEFAULT 0.0,
    stress DOUBLE DEFAULT 0.0,
    valence_base DOUBLE DEFAULT 0.0,
    social_vec DOUBLE[],
    PRIMARY KEY (npc_id, tick)
);

CREATE TABLE IF NOT EXISTS edges (
    tick INTEGER NOT NULL,
    npc_a INTEGER NOT NULL,
    npc_b INTEGER NOT NULL,
    bond DOUBLE NOT NULL,
    PRIMARY KEY (tick, npc_a, npc_b)
);

CREATE TABLE IF NOT EXISTS groups (
    tick INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    poi_id INTEGER,
    poi_name VARCHAR,
    n_members INTEGER,
    PRIMARY KEY (tick, group_id)
);

CREATE TABLE IF NOT EXISTS group_members (
    tick INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    npc_id INTEGER NOT NULL,
    PRIMARY KEY (tick, group_id, npc_id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    tick INTEGER NOT NULL,
    type VARCHAR NOT NULL,
    poi_id INTEGER,
    npc_ids INTEGER[],
    data JSON,
    narrative TEXT
);

CREATE SEQUENCE IF NOT EXISTS seq_event_id START 1;

CREATE TABLE IF NOT EXISTS world_state (
    tick INTEGER PRIMARY KEY,
    year INTEGER NOT NULL,
    week INTEGER NOT NULL,
    season VARCHAR NOT NULL,
    n_alive INTEGER,
    n_births INTEGER DEFAULT 0,
    n_deaths INTEGER DEFAULT 0,
    n_groups INTEGER DEFAULT 0,
    narrative_summary TEXT
);
