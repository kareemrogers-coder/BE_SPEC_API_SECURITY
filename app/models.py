from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Column  
from typing import List
from datetime import date

class Base(DeclarativeBase):
    pass

db= SQLAlchemy(model_class= Base)


service_mechanics = db.Table(
    "service_mechanics",
    Base.metadata,
    Column("ticket_id", db.ForeignKey("service_tickets.id")),
    Column("mechanic_id", db.ForeignKey("mechanics.id"))
)

class Customers(Base):
    __tablename__ = 'customers'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(80), nullable=False)##VARCHAR IN SQL BUT STR IN PYTHON
    email: Mapped[str] = mapped_column(db.String(100), nullable=False, unique=True)
    phone: Mapped[str] = mapped_column(db.String(20))
    password: Mapped[str] = mapped_column(db.String(500), nullable=False) ##added the new "password" field.

    service_tickets: Mapped[List['Service_tickets']] = db.relationship(back_populates = 'customer')

class Service_tickets(Base):
    __tablename__ = 'service_tickets'

    id: Mapped[int] = mapped_column(primary_key=True)
    vin: Mapped[str] = mapped_column(db.String(17), nullable=False, unique=True)
    service_date: Mapped[date] = mapped_column(nullable=False)
    service_desc: Mapped[str] = mapped_column(db.String(1500), nullable=False)
    customer_id: Mapped[int] = mapped_column(db.ForeignKey('customers.id'))

    customer: Mapped['Customers'] = db.relationship(back_populates = 'service_tickets' )

    mechanics: Mapped[List ['Mechanics']] = db.relationship(secondary = service_mechanics, back_populates='service_tickets')

class Mechanics(Base):
    __tablename__ = 'mechanics'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(80), nullable=False)
    email: Mapped[str] = mapped_column(db.String(100), nullable=False, unique=True)
    phone: Mapped[str] = mapped_column(db.String(20), nullable=False ) # requried for contact purpose 
    salary: Mapped[float] = mapped_column(db.Float(7), nullable=False)

    service_tickets: Mapped[List['Service_tickets']] = db.relationship(secondary = service_mechanics, back_populates = 'mechanics')