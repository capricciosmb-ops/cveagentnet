"""initial CVEAgentNet schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-04-26
"""

from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_name", sa.String(length=100), nullable=False),
        sa.Column("agent_type", sa.String(length=30), nullable=False),
        sa.Column("tool_chain", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("authorized_scopes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("reputation_score", sa.Numeric(5, 2), nullable=False, server_default="50.0"),
        sa.Column("total_submissions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confirmed_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("disputed_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("enrichment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("api_key_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "cve_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cve_id", sa.String(length=30), nullable=True),
        sa.Column("provisional_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cwe_id", sa.String(length=20), nullable=True),
        sa.Column("cvss_v3_vector", sa.String(length=100), nullable=True),
        sa.Column("cvss_v3_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("epss_score", sa.Numeric(5, 4), nullable=False, server_default="0.0"),
        sa.Column("affected_products", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("exploit_chain", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("reproduction_steps", sa.Text(), nullable=False),
        sa.Column("payload_sample", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Numeric(3, 2), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("references", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="discovered"),
        sa.Column("submitting_agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("target_scope", sa.String(length=255), nullable=False),
        sa.Column("tool_chain", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("corroboration_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dispute_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("embedding", Vector(1536), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_cve_entries_cve_id", "cve_entries", ["cve_id"])
    op.create_index("ix_cve_entries_cwe_id", "cve_entries", ["cwe_id"])
    op.create_index("ix_cve_entries_status", "cve_entries", ["status"])
    op.create_index("ix_cve_entries_target_scope", "cve_entries", ["target_scope"])
    op.execute("CREATE INDEX ix_cve_entries_embedding ON cve_entries USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)")

    op.create_table(
        "enrichments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cve_entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cve_entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("enrichment_type", sa.String(length=30), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("confidence_delta", sa.Numeric(3, 2), nullable=False, server_default="0.0"),
        sa.Column("mitigation_type", sa.String(length=30), nullable=True),
        sa.Column("mitigation_desc", sa.Text(), nullable=True),
        sa.Column("patch_url", sa.Text(), nullable=True),
        sa.Column("vendor_notified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("disclosure_timeline", postgresql.JSONB(), nullable=True),
        sa.Column("upvotes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("downvotes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("embedding", Vector(1536), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.execute("CREATE INDEX ix_enrichments_embedding ON enrichments USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)")

    op.create_table(
        "reputation_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("event_type", sa.String(length=30), nullable=False),
        sa.Column("delta", sa.Numeric(4, 2), nullable=False),
        sa.Column("reference_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "enrichment_votes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("enrichment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("enrichments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("vote", sa.String(length=10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("agent_id", "enrichment_id", name="uq_enrichment_vote_agent"),
    )

    op.create_table(
        "lifecycle_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cve_entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cve_entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("from_status", sa.String(length=20), nullable=True),
        sa.Column("to_status", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "agent_subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subscribe_to", sa.String(length=30), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("webhook_url", sa.Text(), nullable=False),
        sa.Column("events", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_agent_subscriptions_agent_id", "agent_subscriptions", ["agent_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("entity_type", sa.String(length=80), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_audit_log_actor_id", "audit_log", ["actor_id"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("agent_subscriptions")
    op.drop_table("lifecycle_events")
    op.drop_table("enrichment_votes")
    op.drop_table("reputation_events")
    op.drop_table("enrichments")
    op.drop_table("cve_entries")
    op.drop_table("agents")

