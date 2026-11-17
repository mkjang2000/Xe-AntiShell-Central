package central

const updateSchema = `
CREATE TABLE IF NOT EXISTS feature_schema(name TEXT PRIMARY KEY,version INTEGER NOT NULL);
INSERT INTO feature_schema(name,version) VALUES('agent_updates',1) ON CONFLICT(name) DO NOTHING;
CREATE TABLE IF NOT EXISTS update_releases(id TEXT PRIMARY KEY,metadata_json BLOB NOT NULL,uploaded_by TEXT NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS update_inventory(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,inventory_json BLOB NOT NULL,received_at_ns INTEGER NOT NULL,PRIMARY KEY(agent_id,enrollment_id));
CREATE TABLE IF NOT EXISTS update_rollouts(id TEXT PRIMARY KEY,release_id TEXT NOT NULL,created_by TEXT NOT NULL,created_at_ns INTEGER NOT NULL,expires_at_ns INTEGER NOT NULL,concurrency INTEGER NOT NULL,cancelled INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0,stop_reason TEXT NOT NULL DEFAULT '',request_key TEXT NOT NULL UNIQUE,snapshot_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS update_heads(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 0,active_job_id TEXT NOT NULL DEFAULT '',PRIMARY KEY(agent_id,enrollment_id));
CREATE TABLE IF NOT EXISTS update_jobs(id TEXT PRIMARY KEY,rollout_id TEXT NOT NULL REFERENCES update_rollouts(id),agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,current_json BLOB NOT NULL,target_json BLOB NOT NULL,plan_json BLOB,authorization_json BLOB,expires_at_ns INTEGER NOT NULL,install_deadline_ns INTEGER NOT NULL DEFAULT 0,report_sequence INTEGER NOT NULL DEFAULT 0,report_json BLOB,report_at_ns INTEGER NOT NULL DEFAULT 0,last_report_late INTEGER NOT NULL DEFAULT 0,error_code TEXT NOT NULL DEFAULT '',UNIQUE(agent_id,enrollment_id,revision));
CREATE TABLE IF NOT EXISTS update_reports(job_id TEXT NOT NULL REFERENCES update_jobs(id),sequence INTEGER NOT NULL,body BLOB NOT NULL,received_at_ns INTEGER NOT NULL,PRIMARY KEY(job_id,sequence));
CREATE INDEX IF NOT EXISTS update_jobs_agent_idx ON update_jobs(agent_id,enrollment_id,revision DESC);
CREATE INDEX IF NOT EXISTS update_jobs_rollout_idx ON update_jobs(rollout_id,state,id);
CREATE INDEX IF NOT EXISTS update_jobs_expiry_idx ON update_jobs(state,expires_at_ns);
CREATE INDEX IF NOT EXISTS update_jobs_install_idx ON update_jobs(state,install_deadline_ns);
CREATE INDEX IF NOT EXISTS update_rollouts_time_idx ON update_rollouts(created_at_ns DESC,id DESC);
CREATE INDEX IF NOT EXISTS update_rollouts_release_idx ON update_rollouts(release_id);
`
