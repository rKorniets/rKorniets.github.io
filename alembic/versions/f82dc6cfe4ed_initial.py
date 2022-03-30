"""initial

Revision ID: f82dc6cfe4ed
Revises: cd6a07cb2aa0
Create Date: 2021-11-18 13:11:01.073657

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'f82dc6cfe4ed'
down_revision = 'cd6a07cb2aa0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('UserCreate', 'admin')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('UserCreate', sa.Column('admin', mysql.TINYINT(display_width=1), autoincrement=False, nullable=False))
    # ### end Alembic commands ###