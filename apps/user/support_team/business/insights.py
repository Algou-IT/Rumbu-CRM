from datetime import datetime, timedelta
from sqlalchemy import func, extract
from .... import db
from ....models.shipping.authorization import Authorization 
from ....models.shipping.purchase import Purchase
from ....models.general.user import User
from ....models.general.role import Role
from ....models.general.company import Company
from flask_login import current_user
from sqlalchemy.orm import aliased
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def get_weekly_service_fees(company_id):
    today = datetime.utcnow()
    start_of_week = today - timedelta(days=today.weekday())
    end_of_week = start_of_week + timedelta(days=7)

    logger.debug(f"Calculating service fees for the week from {start_of_week} to {end_of_week} for company {company_id}")

    current_week_authorization_fees = db.session.query(
        func.sum(Authorization.service_fees)
    ).filter(
        Authorization.date >= start_of_week,
        Authorization.date < end_of_week,
        Authorization.company_id == company_id
    ).scalar()

    current_week_purchase_fees = db.session.query(
        func.sum(Purchase.service_fees)
    ).filter(
        Purchase.start_check >= start_of_week,
        Purchase.start_check < end_of_week,
        Purchase.company_id == company_id
    ).scalar()

    current_week_fees = (current_week_authorization_fees or 0) + (current_week_purchase_fees or 0)

    previous_week_start = start_of_week - timedelta(days=7)
    previous_week_end = start_of_week

    logger.debug(f"Calculating service fees for the previous week from {previous_week_start} to {previous_week_end} for company {company_id}")

    previous_week_authorization_fees = db.session.query(
        func.sum(Authorization.service_fees)
    ).filter(
        Authorization.date >= previous_week_start,
        Authorization.date < previous_week_end,
        Authorization.company_id == company_id
    ).scalar()

    previous_week_purchase_fees = db.session.query(
        func.sum(Purchase.service_fees)
    ).filter(
        Purchase.start_check >= previous_week_start,
        Purchase.start_check < previous_week_end,
        Purchase.company_id == company_id
    ).scalar()

    previous_week_fees = (previous_week_authorization_fees or 0) + (previous_week_purchase_fees or 0)

    return current_week_fees, previous_week_fees


def calculate_percentage_difference(current, previous):
    if previous == 0:
        return 100 if current > 0 else 0
    return ((current - previous) / previous) * 100

def get_weekly_financial_summary(company_id):
    current_week_fees, previous_week_fees = get_weekly_service_fees(company_id)
    percentage_difference = calculate_percentage_difference(current_week_fees, previous_week_fees)

    logger.debug(f"Weekly financial summary for company {company_id}: current_week_fees={current_week_fees}, previous_week_fees={previous_week_fees}, percentage_difference={percentage_difference}")

    return {
        'current_week_fees': current_week_fees,
        'previous_week_fees': previous_week_fees,
        'percentage_difference': percentage_difference,
        'status': 'gain' if percentage_difference > 0 else 'loss'
    }


def get_user_role_count(company_id):
    user_role = Role.query.filter_by(position='customer').first()
    if not user_role:
        return 0, 0

    today = datetime.utcnow()
    start_of_current_month = datetime(today.year, today.month, 1)
    start_of_previous_month = (start_of_current_month - timedelta(days=1)).replace(day=1)
    end_of_previous_month = start_of_current_month - timedelta(days=1)

    logger.debug(f"Calculating user role count for role 'User' in company {company_id}")

    current_month_count = db.session.query(func.count(User.id)).filter(
        User.role_id == user_role.id,
        User.member_since >= start_of_current_month,
        User.company_id == company_id
    ).scalar()

    previous_month_count = db.session.query(func.count(User.id)).filter(
        User.role_id == user_role.id,
        User.member_since >= start_of_previous_month,
        User.member_since < start_of_current_month,
        User.company_id == company_id
    ).scalar()

    return current_month_count, previous_month_count


def get_monthly_user_summary(company_id):
    current_count, previous_count = get_user_role_count(company_id)
    percentage_difference = calculate_percentage_difference(current_count, previous_count)

    logger.debug(f"Monthly user summary for company {company_id}: current_count={current_count}, previous_count={previous_count}, percentage_difference={percentage_difference}")

    return {
        'current_count': current_count,
        'previous_count': previous_count,
        'percentage_difference': percentage_difference,
        'status': 'gain' if percentage_difference > 0 else 'loss'
    }


def get_daily_client_count(company_id):
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)

    logger.debug(f"Calculating daily client count for today: {today} and yesterday: {yesterday} for company {company_id}")

    today_authorizations = db.session.query(func.count(Authorization.id)).filter(
        func.date(Authorization.date) == today,
        Authorization.company_id == company_id
    ).scalar()

    today_purchases = db.session.query(func.count(Purchase.id)).filter(
        func.date(Purchase.start_check) == today,
        Purchase.company_id == company_id
    ).scalar()

    yesterday_authorizations = db.session.query(func.count(Authorization.id)).filter(
        func.date(Authorization.date) == yesterday,
        Authorization.company_id == company_id
    ).scalar()

    yesterday_purchases = db.session.query(func.count(Purchase.id)).filter(
        func.date(Purchase.start_check) == yesterday,
        Purchase.company_id == company_id
    ).scalar()

    today_clients = (today_authorizations or 0) + (today_purchases or 0)
    yesterday_clients = (yesterday_authorizations or 0) + (yesterday_purchases or 0)

    return today_clients, yesterday_clients


def get_daily_client_summary(company_id):
    today_clients, yesterday_clients = get_daily_client_count(company_id)
    percentage_difference = calculate_percentage_difference(today_clients, yesterday_clients)

    logger.debug(f"Daily client summary for company {company_id}: today_clients={today_clients}, yesterday_clients={yesterday_clients}, percentage_difference={percentage_difference}")

    return {
        'today_clients': today_clients,
        'yesterday_clients': yesterday_clients,
        'percentage_difference': percentage_difference,
        'status': 'gain' if percentage_difference > 0 else 'loss'
    }


def get_user_invoices(user_id):
    purchases = Purchase.query.filter_by(user_id=user_id, closed=False).all()
    authorizations = Authorization.query.filter_by(user_id=user_id, granted=False).all()

    logger.debug(f"Getting invoices for user_id: {user_id}")

    invoices = []
    for purchase in purchases:
        invoices.append({
            'id': purchase.id,
            'title': purchase.title,
            'amount': purchase.service_fees
        })
    for authorization in authorizations:
        invoices.append({
            'id': authorization.id,
            'title': 'Demande de procuration',
            'amount': authorization.service_fees
        })
    return invoices


def get_classes_for_teacher(company_id):
    """
    implement the logic to get the number
    of classes for a teacher
    """
    pass

def get_students_number(company_id):
    """
    implement the logic to get the number
    of students in classes where the teacher
    teach
    """
    pass

def get_students_number(company_id):
    """
    implement the logic to get the number
    of students in classes where the teacher
    teach
    """
    pass



def get_student_session_avg(company_id):
    """
    implement the logic to get 
    the avg grade of all students
    """
    pass



def last_month_start_date():
    today = datetime.today()
    first_day_of_current_month = today.replace(day=1)
    last_month = first_day_of_current_month - timedelta(days=1)
    return last_month.replace(day=1)

def last_month_end_date():
    today = datetime.today()
    first_day_of_current_month = today.replace(day=1)
    last_day_of_last_month = first_day_of_current_month - timedelta(days=1)
    return last_day_of_last_month




def get_relevant_urls_for_company(company_id):
    """Fetches all relevant file URLs for a company from the database."""
    urls = [] 

    return urls


def get_data_size_for_company(company_id):
    company = Company.query.get(company_id)
    if not company:
        raise ValueError("Company not found")

    total_size = 0

    # Function to calculate the size of data for a given model
    def get_table_data_size(model_class, company_id):
        total_size = 0
        rows = model_class.query.filter_by(company_id=company_id).all()

        # Text columns
        text_columns = [column.name for column in model_class.__table__.columns if isinstance(column.type, db.String)]
        for row in rows:
            for column in text_columns:
                value = getattr(row, column)
                if isinstance(value, str):  # Ensure the value is a string
                    total_size += len(value.encode('utf-8'))  # Size in bytes

        # Integer columns
        int_columns = [column.name for column in model_class.__table__.columns if isinstance(column.type, db.Integer)]
        for row in rows:
            for column in int_columns:
                value = getattr(row, column)
                if value is not None:
                    total_size += 4  # Size of an integer in bytes

        # Float/Decimal columns
        float_columns = [column.name for column in model_class.__table__.columns if isinstance(column.type, (db.Float, db.Numeric))]
        for row in rows:
            for column in float_columns:
                value = getattr(row, column)
                if value is not None:
                    total_size += 8  # Size of a double-precision float in bytes

        # Date/Time columns
        datetime_columns = [column.name for column in model_class.__table__.columns if isinstance(column.type, db.DateTime)]
        for row in rows:
            for column in datetime_columns:
                value = getattr(row, column)
                if value is not None:
                    total_size += 8  # Size of a datetime in bytes

        # Boolean columns
        boolean_columns = [column.name for column in model_class.__table__.columns if isinstance(column.type, db.Boolean)]
        for row in rows:
            for column in boolean_columns:
                value = getattr(row, column)
                if value is not None:
                    total_size += 1  # Size of a boolean in bytes

        return total_size

    # Calculate the size for Company model data
    def get_company_size(company):
        total_size = 0

        # Text columns
        text_columns = [
            'title', 'description', 'logo_url', 'location', 'category', 'nature',
            'email', 'phone_number', 'website_url', 'linkedin_url', 'twitter_url',
            'facebook_url', 'number_of_employees', 'annual_revenue', 'currency', 'tags'
        ]
        for column in text_columns:
            value = getattr(company, column)
            if isinstance(value, str):  # Ensure the value is a string
                total_size += len(value.encode('utf-8'))

        # Integer columns
        int_columns = ['id', 'year_established']
        for column in int_columns:
            value = getattr(company, column)
            if value is not None:
                total_size += 4  # Size of an integer in bytes

        # Float/Decimal columns (if applicable)
        float_columns = []  # Add any float/decimal columns here
        for column in float_columns:
            value = getattr(company, column)
            if value is not None:
                total_size += 8  # Size of a double-precision float in bytes

        # Date/Time columns
        datetime_columns = ['registration_date']
        for column in datetime_columns:
            value = getattr(company, column)
            if value is not None:
                total_size += 8  # Size of a datetime in bytes

        # Boolean columns
        boolean_columns = ['is_active']
        for column in boolean_columns:
            value = getattr(company, column)
            if value is not None:
                total_size += 1  # Size of a boolean in bytes

        return total_size

    # Add company-specific data size
    total_size += get_company_size(company)

    # Include the data size from related tables
    related_tables = [
        User
    ]

    for table in related_tables:
        total_size += get_table_data_size(table, company_id)

    return total_size
