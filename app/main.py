from typing import Optional, Union, List
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Form
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from pymongo import MongoClient
import os
import uuid
from bson import ObjectId

app = FastAPI()



MONGODB_URL = os.getenv("MONGODB_URL")
UPLOAD_DIRECTORY = "./uploads"

client = MongoClient(MONGODB_URL)

# Get the database
db = client['my_event_db']

users_collection = db.users
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
    id: Optional[str] = Field(None, alias="_id")  # The alias is for MongoDB's '_id' field
    username: str
    full_name: Optional[str] = None
    email: str
    disabled: bool = False

    class Config:
        orm_mode = True
        allow_population_by_field_name = True


class UserInDB(BaseModel):
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

@app.post("/signup", response_model=User, tags=["authentication"])
def create_user(user: UserSignUp):
    if user.password != user.repeat_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    result = users_collection.insert_one(user_data)
    user_id = str(result.inserted_id)
    user_data['id'] = user_id
    hashed_password = pwd_context.hash(user.password)
    user_data = user.dict(exclude={"password", "repeat_password"})  # Exclude plaintext passwords
    user_data["hashed_password"] = hashed_password

    users_collection.insert_one(user_data)
    return {**user_data, "password": "", "_id": ""}  # Exclude hashed password in the response

def get_user(username: str):
    user_dict = users_collection.find_one({"username": username})
    if user_dict:
        user_dict.pop('_id')  # Remove the ObjectId
        user_dict.pop('hashed_password')  # Remove the hashed password as it's not needed in the User model
        return UserInDB(**user_dict)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user_dict = users_collection.find_one({"username": username})
    if user_dict and verify_password(password, user_dict["hashed_password"]):
        user_dict['_id'] = str(user_dict['_id'])  # Convert ObjectId to string
        return User(**user_dict)
    return None

@app.post("/login", tags=["authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = user.username
    user_data = user.dict(exclude={"hashed_password", "_id"})
    return {"access_token": token, "token_type": "bearer", "user": user_data}

@app.get("/users/me", response_model=User, tags=["authentication"])
async def read_users_me(current_username: str = Depends(oauth2_scheme)):
    user_dict = get_user(current_username)
    if not user_dict:
        raise HTTPException(status_code=404, detail="User not found")
    if user_dict.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    user_dict['_id'] = str(user_dict['_id'])  # Convert ObjectId to string
    return User(**user_dict)

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
        "latitude": latitude,
        "longitude": longitude,
        "age_range": {
            "min": age_range_min,
            "max": age_range_max
        },
        "type": type,
        "picture": file_path
    }

    events_collection = db.events
    event_data_json = jsonable_encoder(event_data)
    events_collection.insert_one(event_data_json)

    # Return the created event
    return {"detail": "Event created successfully", "event": event_data}

@app.get("/events/{event_id}", response_model=EventCreate, tags=["events"])
async def get_event(event_id: str):
    events_collection = db.events
    event = events_collection.find_one({"_id": event_id})
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    
    event_data = jsonable_encoder(event)
    return event_data

@app.get("/events/picture/{filename}", tags=["events"])
async def get_event_picture(filename: str):
    file_path = os.path.join(UPLOAD_DIRECTORY, filename)
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
