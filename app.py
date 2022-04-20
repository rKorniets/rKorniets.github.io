from marshmallow import fields, validate
from flask import Flask, request, jsonify, make_response, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import bcrypt
import jwt
import datetime
from functools import wraps
# from database import Admin, Film, Timetable, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'il1k3ppv3rymuch'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://python:Qwedcxzas123_@localhost:3306/buying_tickets'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
ma = Marshmallow(app)

salt = bcrypt.gensalt()


class Event(db.Model):
    __tablename__ = 'Event'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    Title = db.Column(db.String(100), nullable=False)

    def __init__(self, title):
        self.Title = title


class EventSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Event
    id = fields.Int(dump_only=True)
    Title = fields.Str(required=True, validate=[validate.Length(min=3, max=36)])


event_schema = EventSchema()
events_schema = EventSchema(many=True)


class User(db.Model):
    __tablename__ = 'UserCreate'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.TEXT, nullable=False)
    admin = db.Column(db.Boolean, nullable=False)

    def __init__(self, username, email, password, admin):
        self.username = username
        self.email = email
        self.password = password
        self.admin = admin


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class Ticket(db.Model):
    __tablename__ = 'Ticket'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    idUser = db.Column(db.Integer)
    idEvent = db.Column(db.ForeignKey('Event.id'), nullable=False)
    is_booked = db.Column(db.Boolean, nullable=False)
    is_solid = db.Column(db.Boolean, nullable=False)

    def __init__(self, idUser, idEvent, is_booked, is_solid):
        self.idUser = idUser
        self.idEvent = idEvent
        self.is_booked = is_booked
        self.is_solid = is_solid


class TicketSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Ticket


ticket_schema = TicketSchema()
tickets_schema = TicketSchema(many=True)


# --------------------------------------------

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'Bearer' in request.headers:
            token = request.headers['Bearer']

        if not token:
            return make_response(jsonify({'message': 'a valid token is missing'}), 403)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return make_response(jsonify({'message': 'token is invalid'}), 403)

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/', methods=['GET', 'POST'])
def main_page():
    """returning main html page"""
    return render_template("index.html")


@app.route('/signin', methods=['GET'])
def login_page():
    return render_template("login.html")


@app.route('/signup', methods=['GET', 'POST'])
def registration_page():
    return render_template("registration.html")


@app.route('/all_events', methods=['GET', 'POST'])
def all_events_page():
    return render_template("all-events.html")


@app.route('/User', methods=['POST'])
def create_user():
    try:
        email = request.json["email"]
        if User.query.filter_by(email=email).first():
            return make_response(jsonify({"message": "E-mail is already in use."}), 400)

        username = request.json["username"]
        if User.query.filter_by(username=username).first():
            return make_response(jsonify({"message": "Username is already in use."}), 400)

        password = request.json["password"]
        if password == "":
            return make_response(jsonify({"message": "Password is too short."}), 400)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt=salt)
        new_user = User(username=username, email=email, password=hashed_password, admin = False);
        db.session.add(new_user)
        db.session.commit()
        return user_schema.jsonify(new_user)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/api/isLoggedIn', methods=['GET'])
@token_required
def is_logged_in(current_user):
    return make_response('', 200)


@app.route('/User/<username>', methods=['GET'])
@token_required
def get_user(current_user, username):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            return user_schema.jsonify(user)
        else:
            return make_response(jsonify({"message": "User not found."}), 404)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/User', methods=['GET'])
@token_required
def get_users(current_user):
    try:
        users = User.query.all()
        return users_schema.jsonify(users)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/User/login', methods=['POST'])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response(jsonify({"message": "User not found."}), 404)

    if not bcrypt.checkpw(auth.password.encode('utf-8'), user.password.encode('utf-8')):
        return make_response(jsonify({"message": "Invalid password."}), 403)

    token = jwt.encode({"username" : auth.username, "exp" : datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, app.config['SECRET_KEY'])
    return jsonify({"token" : token})


@app.route('/User/logout', methods=['GET'])
@token_required
def logout_user(current_user):
    try:
        token = jwt.encode({"username" : current_user.username, "exp" : datetime.datetime.utcnow() + datetime.timedelta(seconds=1)}, app.config['SECRET_KEY'])
        return make_response(jsonify({"message": "Have a nicee day"}), 200)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/User/<username>', methods=['PUT'])
@token_required
def edit_user(current_user, username):
    try:
        if current_user.username != username:
            return make_response(jsonify({"message": "You have no access to do that..."}), 403)
        user = User.query.filter_by(username=username).first()
        if user:
            email = request.json["email"]
            if User.query.filter_by(email=email).first() and User.query.filter_by(email=email).first() != user:
                return make_response(jsonify({"message": "E-mail is already in use."}), 400)

            username = request.json["username"]
            if User.query.filter_by(username=username).first() and user.query.filter_by(username=username).first() != user:
                return make_response(jsonify({"message": "Username is already in use."}), 400)

            password = request.json["password"]
            if len(password) < 6:
                return make_response(jsonify({"message": "Password is too short."}), 400)
            admin = request.json["admin"]
            if admin != 0 and admin != 1:
                return make_response(jsonify({"message": "Incorect data for admin."}), 400)
            if not current_user.admin and admin == 1:
                return make_response(jsonify({"message": "You have no access to do that..."}), 403)
            user.password = bcrypt.hashpw(password.encode('utf-8'), salt=salt)
            user.email = email
            user.username = username
            user.admin = admin
            db.session.commit()
            return user_schema.jsonify(user)
        else:
            return make_response(jsonify({"message": "Unknown user."}), 404)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 404)


@app.route('/User/<username>', methods=['DELETE'])
@token_required
def delete_user(current_user, username):
    try:
        if current_user.username != username:
            return make_response(jsonify({"message": "You have no access to do that..."}), 403)
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return user_schema.jsonify(user)
        else:
            return make_response(jsonify({"message": "User is already deleted or didn't exists."}), 404)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Event', methods=['POST'])
@token_required
def create_event(current_user):
    try:
        if not current_user.admin:
            return make_response(jsonify({"message": "You have no access to do that..."}), 403)
        title = request.json["Title"]
        if Event.query.filter_by(Title=title).first():
            return make_response(jsonify({"message": "Event already exists..."}), 400)
        new_event = Event(title)

        db.session.add(new_event)
        db.session.commit()
        return event_schema.jsonify(new_event)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Event', methods=['GET'])
@token_required
def get_events(current_user):
    try:
        events = Event.query.all()
        return events_schema.jsonify(events)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Event/<int:id>', methods=['GET'])
@token_required
def get_event(current_user, id):
    event = Event.query.get(id)
    if not event:
        return make_response(jsonify({"message": "Unknown event id..."}), 404)
    else:
        return event_schema.dump(event)


@app.route('/Event/<int:id>', methods=['PUT'])
@token_required
def edit_event(current_user, id):
    try:
        if not current_user.admin:
            return make_response(jsonify({"message": "You have no access to do that..."}), 403)
        editing_event = Event.query.get(id)
        if editing_event is not None:
            title = request.json["Title"]
            if len(title) < 3:
                return make_response(jsonify({"message": "Title is too short."}), 400)
            editing_event.Title = title
            db.session.commit()
            return event_schema.jsonify(editing_event)
        else:
            return make_response(jsonify({"message": "Event doesn't exists"}), 400)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Event/<int:id>', methods=['DELETE'])
@token_required
def delete_event(current_user, id):
    if not current_user.admin:
        return make_response(jsonify({"message": "You have no access to do that..."}), 403)
    event = Event.query.get(id)
    if event:
        db.session.delete(event)
        db.session.commit()
        return event_schema.jsonify(event)
    else:
        return make_response(jsonify({"message": "Event is already deleted or didn't exists."}), 404)


@app.route('/Ticket', methods=['POST'])
@token_required
def create_ticket(current_user):
    try:
        if not current_user.admin:
            return make_response(jsonify({"message": "You have no access to do that..."}), 403)
        idEvent = request.json["idEvent"]
        if not Event.query.get(idEvent):
            return make_response(jsonify({"message": "Event doesn't exists. Bad request"}), 400)
        new_ticket = Ticket(idUser=0, idEvent=idEvent, is_booked=False, is_solid=False)
        db.session.add(new_ticket)
        db.session.commit()
        return ticket_schema.jsonify(new_ticket)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Ticket/reserve_ticket', methods=['PUT'])
@token_required
def book_ticket(current_user):
    try:
        idUser = current_user.id

        Title = request.json["Title"]
        current_event = Event.query.filter_by(Title=Title).first()
        new_ticket = Ticket.query.filter_by(idEvent=current_event.id, is_booked=False, is_solid=False).first()
        if not new_ticket:
            return make_response(jsonify({"message": "There is no free ticket to buy"}), 401)

        if new_ticket:
            new_ticket.idUser = idUser
            new_ticket.is_booked = True
            db.session.add(new_ticket)
            db.session.commit()
            return ticket_schema.jsonify(new_ticket)
        else:
            return make_response(jsonify({"message": "There are no tickets, try to create a new one"}), 401)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/allTickets', methods=['GET'])
def get_tickets():
    try:
        tickets = Ticket.query.filter_by(is_solid=False, is_booked=False).all()
        return tickets_schema.jsonify(tickets)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Ticket', methods=['GET'])
@token_required
def get_user_tickets(current_user):
    try:
        tickets = Ticket.query.filter_by(idUser = current_user.id).all()
        return tickets_schema.jsonify(tickets)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Ticket/<int:id>/Buy', methods=['PUT'])
@token_required
def buy_ticket(current_user, id):
    try:
        b_ticket = Ticket.query.get(id)

        if not b_ticket:
            return make_response(jsonify({"message": "Invalid ID supplied. Bad request"}), 400)

        if b_ticket.idUser != current_user.id:
            return make_response(jsonify({"message": "You haven't this ticket"}), 400)

        if b_ticket.is_solid:
            return make_response(jsonify({"message": "You've already bought this ticket."}), 201)
        b_ticket.is_solid = True
        db.session.commit()
        return ticket_schema.jsonify(b_ticket)
    except:
        return make_response(jsonify({"message": "Bad data supplied"}), 405)


@app.route('/Ticket/<int:id>/Cancel_reserve', methods=['PUT'])
@token_required
def unbook_ticket(current_user, id):
    ticket = Ticket.query.get(id)
    if ticket and ticket.idUser == current_user.id:
        if ticket.is_solid:
            return make_response(jsonify({"message": "Ticket is already bought."}), 405)
        else:
            ticket.is_booked=False
            ticket.idUser = 0
            db.session.commit()
            return ticket_schema.jsonify(ticket)
    else:
        return make_response(jsonify({"message": "Ticket is already deleted or didn't exists."}), 400)


if __name__ == '__main__':
    app.run()
