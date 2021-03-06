"""initial

Revision ID: 45a9fde76eb2
Revises: 7900aed9ba11
Create Date: 2021-11-18 13:32:14.041196

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '45a9fde76eb2'
down_revision = '7900aed9ba11'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('UserCreate', 'admin')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('UserCreate', sa.Column('admin', mysql.VARCHAR(length=45), nullable=False))
    # ### end Alembic commands ###
