"""
Database Schemas for the SaaS app

Each Pydantic model represents a collection in MongoDB. The collection name
is the lowercase of the class name (e.g., User -> "user").
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any

class User(BaseModel):
    """
    Users collection schema
    Stores profile fields. Passwords are stored as hashed strings in the database.
    """
    email: EmailStr = Field(..., description="Email address (unique)")
    name: Optional[str] = Field(None, description="Display name")
    password_hash: str = Field(..., description="BCrypt hash of the user's password")

class Event(BaseModel):
    """
    Analytics events
    """
    user_id: str = Field(..., description="ID of the user who generated the event")
    type: str = Field(..., description="Event type, e.g., 'page_view', 'click'")
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional event props")
