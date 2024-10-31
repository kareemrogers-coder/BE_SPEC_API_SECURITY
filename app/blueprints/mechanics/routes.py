from app.blueprints.mechanics import mechanics_bp

from .schemas import mechanic_schema, mechanics_schema
from flask import request, jsonify
from marshmallow import ValidationError
from app.models import Mechanics, db
from sqlalchemy import select





@mechanics_bp.route("/", methods =['POST'])
def create_mechanic():
    try: # validation error, this type of error handling, handles commands that isnt recognizable 
        mechanic_data = mechanic_schema.load(request.json) # command this is to load only validate information
    except ValidationError as e:
        return jsonify(e.messages), 400
    
    new_mechanic = Mechanics(name=mechanic_data['name'], email=mechanic_data['email'], phone=mechanic_data['phone'], salary=mechanic_data['salary'])
    db.session.add(new_mechanic) # add to session
    db.session.commit() #upload info to database

    return jsonify("Mechanic has been added our database."), 201


@mechanics_bp.route("/", methods =['GET'])
def get_mechanics():
    query = select(Mechanics)
    mechanics = db.session.execute(query).scalars().all()

    return mechanics_schema.jsonify(mechanics), 200





@mechanics_bp.route ("/<int:mechanic_id>", methods=['GET'])
def get_mechanic(mechanic_id):
    mechanic = db.session.get(Mechanics, mechanic_id )

    return mechanic_schema.jsonify(mechanic), 200


@mechanics_bp.route("/<int:mechanic_id>", methods =['PUT'])
def update_mechanic(mechanic_id):
    mechanic = db.session.get(Mechanics, mechanic_id)

    if mechanic == None:
        return jsonify ({"message": "invalid id"}), 400
    
    try:
        mechanic_data = mechanic_schema.load(request.json)
    except ValidationError as e:
        return jsonify(e.messages), 400
    
    for field, value in mechanic_data.items():
        if value:
            setattr(mechanic, field, value)

    db.session.commit()
    return mechanic_schema.jsonify(mechanic), 200



@mechanics_bp.route("/<int:mechanic_id>", methods=['DELETE'])
def delete_mechanic(mechanic_id):
    mechanic = db.session.get(Mechanics, mechanic_id)

    if mechanic == None:
        return jsonify({"message": "invalid id"}), 400

    db.session.delete(mechanic)
    db.session.commit()
    return jsonify({"message": f"User at ID {mechanic_id}  has been deleted "})
