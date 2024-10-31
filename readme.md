## Enhancing Security with JWT Tokens in Factory Management System

**Objective:** The objective of this assignment is to implement JWT token-based authentication and authorization in the factory management system to ensure secure access to resources and endpoints.

**Problem Statement:** You are tasked with enhancing the security of the factory management system by implementing JWT token-based authentication and authorization. This involves generating JWT tokens for user authentication and adding role-based access control to endpoints to restrict access based on user roles.

Task 1: Implement JWT Token Generation

- Add the pyjwt library to the requirements.txt file to enable JWT token generation and validation.
```txt
PyJWT==2.9.0
```

- Create a utils folder and generate the util.py file to create tokens and validate tokens as required.

- Define a secret key to be used for creating the JWT tokens.


- Implement a function named encode_token(user_id) in util.py to generate JWT tokens with an expiration time, issued time (iat), and user ID as the payload.




**Task 2: Authentication Logic**

- Before we can allow our Customers to login, we need to add a password field to the Customer model (This will require dropping your tables).

- Create a login route for your Customer blueprint that takes in email and password.
- Verify a customer exists with that email, and check the stored hashed password against the one passed in.
    - from werkzeug.security import generate_password_hash, check_password_hash.

```py
class Customers(Base):
    __tablename__ = 'customers'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(80), nullable=False)##VARCHAR IN SQL BUT STR IN PYTHON
    email: Mapped[str] = mapped_column(db.String(100), nullable=False, unique=True)
    phone: Mapped[str] = mapped_column(db.String(20))
    password: Mapped[str] = mapped_column(db.String(500), nullable=False) ##added the new "password" field.
```

- Now when we create customers using our POST /customers endpoint we need to make sure store the Hashed password to keep the password protected.
    - from werkzeug.security import generate_password_hash.
````py
@customers_bp.route("/", methods =['POST'])
def create_customer():
    try: # validation error, this type of error handling, handles commands that isnt recognizable 
        customer_data = customer_schema.load(request.json) # command this is to load only validate information
    except ValidationError as e:
        return jsonify(e.messages), 400
    
    pwhash = generate_password_hash(customer_data['password'])
    new_customer = Customers(name=customer_data['name'], email=customer_data['email'], phone=customer_data['phone'], password = pwhash)
    db.session.add(new_customer) # add to session
    db.session.commit() #upload info to database

    return jsonify("Customer has been added our database."), 201

````


```py
@customers_bp.route("/login", methods=['POST'])
def login():
    try:
        creds = login_schema.load(request.json)

    except ValidationError as e :
        return jsonify(e.messages), 400
    
    query = select(Customers).where(Customers.email == creds['email'])
    customer = db.session.execute(query).scalars().first()

    # if customer and customer.password == creds['password']:
    if customer and check_password_hash(customer.password, creds['password']):
        token = encode_token(customer.id)

        response = {
            "message": " You're are logged in",
            "status": "Success",
            "token": token
        }
    
    return jsonify(response), 200
```



- Utilize the encode_token function from the util.py module you created to generate the JWT token with the customer ID in the payload.

- Return the JWT token along with a success message upon successful authentication.

**Task 3: Create a token_required wrapper**

- Back in the util.py file, create a wrapper that will validate your tokens past in as Authorization headers.
- Remember the value of your auth header 'Authorization: 'Bearer <token>'
Ensure to let the user know if the token has expired, or is invalid


```py
def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split()[1]
                payload = jwt.decode(token, SECRET_KEY, algorithms='****')
                print("PAYLOAD:", payload)       
            except jwt.ExpiredSignatureError:
                return jsonify({'message': "Token has expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"message": "Invalid Token"}), 401  

            return func(*args, **kwargs)
        else:
            return jsonify({"messages": "Token Authorization required"}), 401
        
    return wrapper
```


**Task 4: Add access control**

- Utilize your @token_required wrapper on resources, you think the user should be logged in to use. (apply it to at least one controller)

**Login and Token neededed to delete user**
```py
from app.utlis.util import encode_token, token_required

@customers_bp.route("/<int:customer_id>", methods=['DELETE'])
@token_required
def delete_customer(customer_id):
    customer = db.session.get(Customers, customer_id)

    if customer == None:
        return jsonify({"message": "invalid id"}), 400

    db.session.delete(customer)
    db.session.commit()
    return jsonify({"message": f"User at ID {customer_id}  has been deleted "})
```

**Login and Token needed to update customer profile**

```py
@customers_bp.route("/<int:customer_id>", methods =['PUT'])
@token_required
def update_customer(customer_id):
    customer = db.session.get(Customers, customer_id)

    if customer == None:
        return jsonify ({"message": "invalid id"}), 400
    
    try:
        customer_data = customer_schema.load(request.json)
    except ValidationError as e:
        return jsonify(e.messages), 400
    
    for field, value in customer_data.items():
        if value:
            setattr(customer, field, value)

    db.session.commit()
    return customer_schema.jsonify(customer), 200
```