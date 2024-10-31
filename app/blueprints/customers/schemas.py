from  app.models import Customers
from app.extensions import ma


class CustomersSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Customers



customer_schema = CustomersSchema()
customers_schema = CustomersSchema(many=True)
login_schema = CustomersSchema(exclude=['name', 'phone'])