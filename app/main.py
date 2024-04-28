from typing import Optional, Union
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from pymongo import MongoClient
import os

app = FastAPI()



MONGODB_URL = os.getenv("MONGODB_URL")

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
    username: str
    full_name: Optional[str] = None
    email: str
    password: str  # Include password for signup
    disabled: bool = False


    class Config:
        orm_mode = True


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



def fake_hash_password(password: str):
    return pwd_context.hash(password)

@app.post("/signup", response_model=User, tags=["authentication"])
def create_user(user: UserSignUp):
    if user.password != user.repeat_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = pwd_context.hash(user.password)
    user_data = user.dict(exclude={"password", "repeat_password"})  # Exclude plaintext passwords
    user_data["hashed_password"] = hashed_password

    users_collection.insert_one(user_data)
    return {**user_data, "password": ""}  # Exclude hashed password in the response



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
        return UserInDB(**user_dict)
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
    user = get_user(current_username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user.dict(exclude={"hashed_password", "_id"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
