"""add non-secret agent API key lookup prefix

Revision ID: 0004_agent_key_prefix
Revises: 0003_abuse_trust
Create Date: 2026-04-27
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_agent_key_prefix"
down_revision = "0003_abuse_trust"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable preserves existing bcrypt-only keys; newly issued and rotated keys
    # receive a prefix so auth can avoid scanning every active agent hash.
    op.add_column("agents", sa.Column("api_key_prefix", sa.String(length=24), nullable=True))
    op.create_index("uq_agents_api_key_prefix", "agents", ["api_key_prefix"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_agents_api_key_prefix", table_name="agents")
    op.drop_column("agents", "api_key_prefix")
