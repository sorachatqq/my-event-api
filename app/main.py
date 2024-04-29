from random import randint
from typing import Optional, Union, List, Any
from wsgiref.validate import validator
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Form, Query, Body, Security
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pymongo import MongoClient, GEOSPHERE
from pydantic import BaseModel, Field, validator, EmailStr
import os
import uuid
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY = "a_very_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, adjust this for production
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

MONGODB_URL = os.getenv("MONGODB_URL")
UPLOAD_DIRECTORY = "./uploads"

client = MongoClient(MONGODB_URL)

# Get the database
db = client['my_event_db']

users_collection = db.users
events_collection = db.events
registrations_collection = db.registrations

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database simulation
users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("secret"),
        "disabled": False,
    }
}

# Check current indexes on the events collection
indexes = events_collection.index_information()
print(indexes)



class TokenData(BaseModel):
    username: Optional[str] = None

class AgeRange(BaseModel):
    min: Optional[int] = Field(None, ge=0, le=150)
    max: Optional[int] = Field(None, ge=0, le=150)

class EventCreate(BaseModel):
    name: str
    description: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    age_range_min: Optional[int] = None
    age_range_max: Optional[int] = None
    type: str
    approved: bool = False
    is_open_for_registration: bool = True

class EventRegistration(BaseModel):
    user_id: str
    event_id: str
    registration_code: Optional[str] = None

class Location(BaseModel):
    type: str
    coordinates: List[float]

class AgeRange(BaseModel):
    min: Optional[int]
    max: Optional[int]

class GetEvent(BaseModel):
    id: Any = Field(None, alias="_id")
    name: str
    description: str
    location: Location
    age_range: AgeRange
    type: str
    picture: Optional[str]

    @validator('id', pre=True, always=True)
    def stringify_id(cls, v):
        return str(v) if isinstance(v, (ObjectId, int)) else v

    class Config:
        orm_mode = True
        allow_population_by_field_name = True
        json_encoders = {
            ObjectId: lambda v: str(v),
        }

class UserSignUp(BaseModel):
    username: str
    email: str
    password: str
    repeat_password: str
    full_name: Optional[str] = None
    gender: Optional[str] = None
    age: Optional[int] = None
    interest_thing: Optional[str] = None


class User(BaseModel):
    id: Any = Field(None, alias="_id")
    username: str
    full_name: Optional[str] = None
    email: str
    disabled: bool = False
    role: str = "user"

    @validator('id', pre=True, always=True)
    def stringify_id(cls, v):
        return str(v) if isinstance(v, (ObjectId, int)) else v

    class Config:
        orm_mode = True
        allow_population_by_field_name = True
        json_encoders = {
            ObjectId: lambda v: str(v),
        }

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class UserInDB(BaseModel):
    id: Any = Field(None, alias="_id")
    username: str
    full_name: str = None
    email: str
    hashed_password: str
    disabled: bool = False

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "username": "johndoe",
                "full_name": "John Doe",
                "email": "johndoe@example.com",
                "hashed_password": "hashed_password",
                "disabled": False
            }
        }

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None 
    disabled: Optional[bool] = None


class NearbySearch(BaseModel):
    latitude: float = Field(..., ge=-90.0, le=90.0, description="Latitude of the location")
    longitude: float = Field(..., ge=-180.0, le=180.0, description="Longitude of the location")
    radius: float = Field(..., description="Radius in kilometers to search for nearby events")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/signup", response_model=User, tags=["authentication"])
def create_user(user: UserSignUp):
    if user.password != user.repeat_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already registered")
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    hashed_password = pwd_context.hash(user.password)
    user_data = user.dict(exclude={"password", "repeat_password"})
    user_data["hashed_password"] = hashed_password

    result = users_collection.insert_one(user_data)
    user_data['id'] = str(result.inserted_id)
    user_data['disabled'] = False

    # Make sure to exclude sensitive fields in the response
    del user_data["hashed_password"]
    return user_data

def get_user(username: str):
    user_record = users_collection.find_one({"username": username})
    if user_record:
        user_record['_id'] = str(user_record['_id'])
        return User(**user_record)
    else:
        return None  # or raise an HTTPException indicating the user is not found

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user_dict = users_collection.find_one({"username": username})
    if user_dict and 'hashed_password' in user_dict and verify_password(password, user_dict["hashed_password"]):
        user_dict['_id'] = str(user_dict['_id'])  # Convert ObjectId to string
        return User(**user_dict)
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = get_user(username=username)  # You need to implement the get_user function.
        if user is None:
            raise credentials_exception
        if user.disabled:  # Here you access the 'disabled' attribute of the user object.
            raise HTTPException(status_code=400, detail="Inactive user")
    except JWTError:
        raise credentials_exception
    return user

@app.post("/token", response_model=Token, tags=["authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    user_data = user.dict(exclude={"hashed_password", "_id"})

    return {"access_token": access_token, "token_type": "bearer", "user": user_data}

@app.patch("/users/update/{user_id}", response_model=User, tags=["user management"])
async def update_user_profile(
    user_id: str, 
    user_update: UserUpdate, 
    current_user: User = Depends(get_current_user)
):
    # Authorization: Ensure only admins can change roles or you can add more complex logic
    # if user_update.role and current_user.role != "admin":
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to change roles")

    # Retrieve the existing user
    existing_user = users_collection.find_one({"_id": user_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields if provided
    update_data = user_update.dict(exclude_unset=True)
    if update_data:
        users_collection.update_one({"_id": user_id}, {"$set": update_data})

    # Fetch the updated user to return
    updated_user = users_collection.find_one({"_id": user_id})
    if updated_user:
        updated_user['id'] = updated_user['_id']
        del updated_user['_id']
        return User(**updated_user)
    else:
        raise HTTPException(status_code=404, detail="User not found after update")


@app.post("/events/create", tags=["events"])
async def create_event(
    name: str = Form(...),
    description: str = Form(...),
    latitude: Optional[float] = Form(None, ge=-90.0, le=90.0),
    longitude: Optional[float] = Form(None, ge=-180.0, le=180.0),
    age_range_min: Optional[int] = Form(None, ge=0, le=150),
    age_range_max: Optional[int] = Form(None, ge=0, le=150),
    type: str = Form(...),
    picture: Optional[UploadFile] = File(None)
):
    os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
    # Handle file upload
    if picture:
        filename = f"{uuid.uuid4()}_{picture.filename}"
        file_path = os.path.join(UPLOAD_DIRECTORY, filename)
        try:
            with open(file_path, 'wb') as image:
                content = await picture.read()
                image.write(content)
        except IOError as e:
            raise HTTPException(status_code=500, detail=f"Could not save file: {e}")
    
    counter = db.counters.find_one_and_update(
        {"_id": "event_id"},
        {"$inc": {"count": 1}},
        new=True,
        upsert=True
    )
    event_id = counter['count']


    # Prepare event data
    event_data = {
        "_id": event_id,
        "name": name,
        "description": description,
        "location": {
            "type": "Point",
            "coordinates": [longitude, latitude]
        },
        "age_range": {
            "min": age_range_min,
            "max": age_range_max
        },
        "type": type,
        "picture": file_path if picture else None
    }


    event_data_json = jsonable_encoder(event_data)
    events_collection.insert_one(event_data_json)

    # Return the created event
    return {"detail": "Event created successfully", "event": event_data}

@app.get("/events/{event_id}", response_model=GetEvent, tags=["events"])
async def get_event(event_id: str):
    try:
        event_id_int = int(event_id)  # Convert if ID is numeric
    except ValueError:
        raise HTTPException(status_code=400, detail="Event ID must be an integer")

    event = events_collection.find_one({"_id": event_id_int})
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    
    event['id'] = event['_id']
    del event['_id'] 
    return event

@app.get("/events/picture/{filename}", tags=["events"])
async def get_event_picture(filename: str):
    file_path = os.path.join(UPLOAD_DIRECTORY, filename)
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)

@app.get("/events/{event_id}/picture", tags=["events"])
async def get_event_picture(event_id: str):
    try:
        event_id_int = int(event_id)  # if event_id is expected to be an integer
    except ValueError:
        raise HTTPException(status_code=400, detail="Event ID must be an integer")

    event = events_collection.find_one({"_id": event_id_int})
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    file_path = event.get("picture")
    if not file_path or not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Serve the picture file
    return FileResponse(file_path)

@app.get("/events", response_model=List[GetEvent], tags=["events"])
async def get_all_events():
    events_cursor = events_collection.find({})
    events_list = list(events_cursor)
    return [GetEvent(**event) for event in events_list]

@app.post("/events/register/{event_id}", response_model=EventRegistration, tags=["events"])
async def register_for_event(event_id: str, current_user: User = Depends(get_current_user)):
    event = events_collection.find_one({"_id": event_id})
    if not event or not event.get('is_open_for_registration', False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This event is not open for registration.")

    existing_registration = registrations_collection.find_one({"user_id": current_user.id, "event_id": event_id})
    if existing_registration:
        return existing_registration  # User already registered, return existing code

    # Register the user and generate a code
    registration_code = ''.join([str(randint(0, 9)) for _ in range(6)])
    registration = {
        "user_id": current_user.id,
        "event_id": event_id,
        "registration_code": registration_code
    }
    registrations_collection.insert_one(registration)
    return registration

@app.post("/home/nearby", response_model=List[GetEvent], tags=["home"])
async def get_nearby_events(search_params: NearbySearch = Body(...)):
    # Convert radius from kilometers to meters
    radius_in_meters = search_params.radius * 1000
    query = {
        "location": {
            "$near": {
                "$geometry": {
                    "type": "Point",
                    "coordinates": [search_params.longitude, search_params.latitude]
                },
                "$maxDistance": radius_in_meters
            }
        }
    }
    try:
        events = list(events_collection.find(query))
        return [GetEvent(**event) for event in events]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/events/update/{event_id}", response_model=GetEvent, tags=["admin", "events"])
async def update_event(
    event_id: str, 
    is_open_for_registration: Optional[bool] = Query(None, description="Open or close event for registration"),
    approved: Optional[bool] = Query(None, description="Approve or disapprove the event"),
    current_user: User = Depends(get_current_user)
):
    # Check if the current user is an admin
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to perform this action")

    # Retrieve the existing event
    existing_event = events_collection.find_one({"_id": event_id})
    if not existing_event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Update fields
    update_data = {}
    if is_open_for_registration is not None:
        update_data['is_open_for_registration'] = is_open_for_registration
    if approved is not None:
        update_data['approved'] = approved

    if update_data:
        events_collection.update_one({"_id": event_id}, {"$set": update_data})

    # Fetch the updated event to return
    updated_event = events_collection.find_one({"_id": event_id})
    if updated_event:
        updated_event['id'] = updated_event['_id']
        del updated_event['_id']
        return updated_event
    else:
        raise HTTPException(status_code=404, detail="Event not found after update")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
