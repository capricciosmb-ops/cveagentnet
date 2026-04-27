"""enforce unique CVE identifiers

Revision ID: 0002_unique_cve_id
Revises: 0001_initial_schema
Create Date: 2026-04-26
"""

from alembic import op

revision = "0002_unique_cve_id"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The API rejects duplicate CVE IDs before insert; this index is the concurrency backstop.
    op.create_index("uq_cve_entries_cve_id", "cve_entries", ["cve_id"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_cve_entries_cve_id", table_name="cve_entries")
