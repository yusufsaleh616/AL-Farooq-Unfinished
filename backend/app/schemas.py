"""Request bodies. The max_length limits are there so nobody can send us huge
strings (a very long password would make Argon2 waste a lot of time)."""
from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    username: str = Field(max_length=64)
    email: str = Field(max_length=254)
    phone: str = Field(max_length=32)
    password: str = Field(max_length=128)
    confirm_password: str = Field(max_length=128)


class DeviceRequestIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)
    public_key: str = Field(max_length=200)
    fp_hash: str = Field(max_length=128)


class ChallengeIn(BaseModel):
    username: str = Field(max_length=64)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)
    device_id: int
    nonce: str = Field(max_length=100)
    fp_hash: str = Field(max_length=128)
    signature: str = Field(max_length=200)


class RedeemIn(BaseModel):
    token: str = Field(max_length=200)
