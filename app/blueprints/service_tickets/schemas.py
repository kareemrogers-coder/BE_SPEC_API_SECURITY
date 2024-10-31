from  app.models import Service_tickets
from app.extensions import ma
from marshmallow import fields


# class Service_ticketsSchema(ma.SQLAlchemyAutoSchema):
#     class Meta:
#         model = Service_tickets


#### manual breakdown of the creating a schema.

# class Service_ticketsSchema(ma.Schema):
#     id = fields.Integer(required=False)
#     vin = fields.String(required=True)
#     service_date = fields.Date(required=True)
#     service_desc = fields.String(required=True)
#     customer_id = fields.Integer(required=True)

#     class Meta:
#         fields = ("vin", "service_date", "service_desc", "customer_id",'id')

### Auto schemca that includes foreign keys.

class Service_ticketsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Service_tickets
        include_fk = True



service_ticket_schema = Service_ticketsSchema()
service_tickets_schema = Service_ticketsSchema(many=True)