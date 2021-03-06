"""initial

Revision ID: d6bfb0cff5b7
Revises: b90e0e516fc4
Create Date: 2021-11-18 13:37:42.286646

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd6bfb0cff5b7'
down_revision = 'b90e0e516fc4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('UserCreate', sa.Column('admin', sa.String(length=45), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('UserCreate', 'admin')
    # ### end Alembic commands ###
