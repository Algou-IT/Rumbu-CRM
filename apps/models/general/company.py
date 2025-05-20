from ... import db

class Company(db.Model):
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False, unique=False)
    description = db.Column(db.Text)
    logo_url = db.Column(db.String)
    location = db.Column(db.String, nullable=False)
    nif = db.Column(db.String)
    rccm = db.Column(db.String)
    capital_social = db.Column(db.String)  # Social capital of the company
    nature = db.Column(db.String)
    email = db.Column(db.String, nullable=False, unique=True)
    phone_number = db.Column(db.String)
    website_url = db.Column(db.String)
    linkedin_url = db.Column(db.String)
    twitter_url = db.Column(db.String)
    facebook_url = db.Column(db.String)
    number_of_employees = db.Column(db.String)
    year_established = db.Column(db.Integer)
    annual_revenue = db.Column(db.String)
    currency = db.Column(db.String, default='USD')
    is_active = db.Column(db.Boolean, default=True)
    registration_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    
    # user specific
    users = db.relationship('User', backref='company', lazy=True)

    notes = db.relationship('Note', backref='company', lazy=True)
    employees = db.relationship('Employee', backref='company', lazy=True)

    
    
    def __init__(self, title, logo_url, location, nature, email, description=None, phone_number=None, website_url=None, linkedin_url=None, twitter_url=None, facebook_url=None, number_of_employees=None, year_established=None, annual_revenue=None, is_active=True, registration_date=None, tags=None):
        self.title = title
        self.description = description
        self.logo_url = logo_url
        self.location = location
        self.nature = nature
        self.email = email
        self.phone_number = phone_number
        self.website_url = website_url
        self.linkedin_url = linkedin_url
        self.twitter_url = twitter_url
        self.facebook_url = facebook_url
        self.number_of_employees = number_of_employees
        self.year_established = year_established
        self.annual_revenue = annual_revenue
        self.is_active = is_active
        self.registration_date = registration_date or db.func.current_timestamp()
        self.tags = tags