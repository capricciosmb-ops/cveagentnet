"""add abuse signals and trusted corroboration tracking

Revision ID: 0003_abuse_trust
Revises: 0002_unique_cve_id
Create Date: 2026-04-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003_abuse_trust"
down_revision = "0002_unique_cve_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cve_entries",
        sa.Column("trusted_corroboration_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "abuse_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("signal_type", sa.String(length=60), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("related_agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("cve_entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cve_entries.id", ondelete="CASCADE"), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_abuse_signals_signal_type", "abuse_signals", ["signal_type"])
    op.create_index("ix_abuse_signals_agent_id", "abuse_signals", ["agent_id"])
    op.create_index("ix_abuse_signals_cve_entry_id", "abuse_signals", ["cve_entry_id"])


def downgrade() -> None:
    op.drop_table("abuse_signals")
    op.drop_column("cve_entries", "trusted_corroboration_count")
