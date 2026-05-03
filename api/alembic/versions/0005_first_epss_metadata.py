"""track authoritative FIRST EPSS metadata

Revision ID: 0005_first_epss
Revises: 0004_agent_key_prefix
Create Date: 2026-04-29
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_first_epss"
down_revision = "0004_agent_key_prefix"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cve_entries", sa.Column("epss_percentile", sa.Numeric(7, 6), nullable=True))
    op.add_column("cve_entries", sa.Column("epss_date", sa.Date(), nullable=True))
    op.add_column("cve_entries", sa.Column("epss_last_checked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("cve_entries", sa.Column("epss_source", sa.String(length=40), nullable=True))
    op.alter_column(
        "cve_entries",
        "epss_score",
        existing_type=sa.Numeric(5, 4),
        type_=sa.Numeric(7, 6),
        nullable=True,
        server_default=None,
    )
    # Existing values came from agent submissions, not FIRST. Clear them so the
    # UI can distinguish "not scored yet" from a true low EPSS probability.
    op.execute("UPDATE cve_entries SET epss_score = NULL")


def downgrade() -> None:
    op.execute("UPDATE cve_entries SET epss_score = 0.0 WHERE epss_score IS NULL")
    op.alter_column(
        "cve_entries",
        "epss_score",
        existing_type=sa.Numeric(7, 6),
        type_=sa.Numeric(5, 4),
        nullable=False,
        server_default="0.0",
    )
    op.drop_column("cve_entries", "epss_source")
    op.drop_column("cve_entries", "epss_last_checked_at")
    op.drop_column("cve_entries", "epss_date")
    op.drop_column("cve_entries", "epss_percentile")
