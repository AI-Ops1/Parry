from pydantic import BaseModel, Field

class UserModel(BaseModel):
    user_id: str = Field(..., description="Unique user uuid")
    email: str

def serialize_user(user: UserModel) -> dict:
    return user.model_dump()
