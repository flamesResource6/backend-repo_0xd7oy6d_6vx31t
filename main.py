import os
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from passlib.context import CryptContext
from jose import jwt, JWTError

from database import db, create_document, get_documents
from schemas import User, Event

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="SaaS Analytics API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuthRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    email: EmailStr
    name: Optional[str] = None

class EventIn(BaseModel):
    type: str
    properties: Optional[Dict[str, Any]] = None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_token(email: str) -> str:
    payload = {"sub": email, "iat": int(datetime.utcnow().timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(token: str = None):
    # simple dependency to decode token
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        # find user
        users = db["user"].find_one({"email": email}) if db else None
        if not users:
            raise HTTPException(status_code=401, detail="User not found")
        return users
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/")
def root():
    return {"message": "SaaS Analytics Backend Running"}


@app.post("/auth/register", response_model=AuthResponse)
def register(payload: AuthRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # unique email check
    if db["user"].find_one({"email": str(payload.email)}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = User(email=str(payload.email), name=None, password_hash=hash_password(payload.password))
    create_document("user", user_doc)
    token = create_token(str(payload.email))
    return {"token": token, "email": str(payload.email), "name": None}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: AuthRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": str(payload.email)})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(str(payload.email))
    return {"token": token, "email": str(payload.email), "name": user.get("name")}


@app.post("/events")
def track_event(event: EventIn, authorization: Optional[str] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    email = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
            email = payload.get("sub")
        except JWTError:
            pass
    data = Event(user_id=email or "anonymous", type=event.type, properties=event.properties or {})
    create_document("event", data)
    return {"status": "ok"}


@app.get("/analytics/summary")
def analytics_summary(authorization: Optional[str] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # Basic counts per type
    pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    results = list(db["event"].aggregate(pipeline))
    summary = {r["_id"]: r["count"] for r in results}
    total = sum(summary.values())
    return {"total": total, "byType": summary}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = getattr(db, 'name', '✅ Connected')
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
