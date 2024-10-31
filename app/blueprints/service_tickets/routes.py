from app.blueprints.service_tickets import service_tickets_bp

from .schemas import service_ticket_schema, service_tickets_schema
from flask import request, jsonify
from marshmallow import ValidationError
from app.models import Service_tickets, db
from sqlalchemy import select
# from datetime import date, datetime




### create a new service ticekt
@service_tickets_bp.route("/", methods =['POST'])
def create_new_service_ticket():
    try: # validation error, this type of error handling, handles commands that isnt recognizable 
        service_ticket_data = service_ticket_schema.load(request.json) # command this is to load only validate information
    except ValidationError as e:
        return jsonify(e.messages), 400
    
    new_ticket = Service_tickets(vin=service_ticket_data['vin'], service_date=service_ticket_data['service_date'], service_desc=service_ticket_data['service_desc'], customer_id = service_ticket_data['customer_id'])
    db.session.add(new_ticket) # add to session
    db.session.commit() #upload info to database

    return jsonify("new service ticket has been added our database."), 201


###retrieve all service tickets

@service_tickets_bp.route("/", methods =['GET'])
def get_service_tickets():
    query = select(Service_tickets)
    service_tickets = db.session.execute(query).scalars().all()

    return service_tickets_schema.jsonify(service_tickets), 200




### retrieve a particular ticket

@service_tickets_bp.route ("/<int:service_ticket_id>", methods=['GET'])
def get_service_ticket(service_ticket_id):
    service_ticket = db.session.get(Service_tickets, service_ticket_id )

    return service_ticket_schema.jsonify(service_ticket), 200


@service_tickets_bp.route("/<int:service_ticket_id>", methods =['PUT'])
def update_service_ticket(service_ticket_id):
    service_ticket = db.session.get(Service_tickets, service_ticket_id)

    if service_ticket== None:
        return jsonify ({"message": "invalid id"}), 400
    
    try:
        service_ticket_data = service_ticket_schema.load(request.json)
    except ValidationError as e:
        return jsonify(e.messages), 400
    
    for field, value in service_ticket_data.items():
        if value:
            setattr(service_ticket, field, value)

    db.session.commit()
    return service_ticket_schema.jsonify(service_ticket), 200



@service_tickets_bp.route("/<int:service_ticket_id>", methods=['DELETE'])
def delete_service_ticekt(service_ticket_id):
    service_ticket = db.session.get(Service_tickets, service_ticket_id)

    if service_ticket == None:
        return jsonify({"message": "invalid id"}), 400

    db.session.delete(service_ticket)
    db.session.commit()
    return jsonify({"message": f"User at ID {service_ticket_id}  has been deleted "})