"""initial

Revision ID: acd9b3d639ff
Revises: d6bfb0cff5b7
Create Date: 2021-11-18 13:40:26.766202

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'acd9b3d639ff'
down_revision = 'd6bfb0cff5b7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('UserCreate',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=40), nullable=False),
    sa.Column('email', sa.String(length=50), nullable=False),
    sa.Column('password', sa.TEXT(), nullable=False),
    sa.Column('admin', sa.String(length=45), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Ticket',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('idUser', sa.Integer(), nullable=True),
    sa.Column('idEvent', sa.Integer(), nullable=False),
    sa.Column('is_booked', sa.Boolean(), nullable=False),
    sa.Column('is_solid', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['idEvent'], ['Event.id'], ),
    sa.ForeignKeyConstraint(['idUser'], ['UserCreate.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('Ticket')
    op.drop_table('UserCreate')
    # ### end Alembic commands ###
