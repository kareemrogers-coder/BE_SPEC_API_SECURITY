from  app.models import Mechanics
from app.extensions import ma


class MechanicsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Mechanics

mechanic_schema = MechanicsSchema()
mechanics_schema = MechanicsSchema(many=True)