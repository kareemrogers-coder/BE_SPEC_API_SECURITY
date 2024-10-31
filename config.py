import os 

class DevelopmentConfig:
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI') #used to hide sensitive information 
    DEBUG = True


class TestingConfig:
    pass


class ProductionConfig:
    pass