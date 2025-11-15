from pydantic import BaseModel
class SampleCreate(BaseModel):
    filename: str

class SampleOut(BaseModel):
    id: int
    filename: str
    path: str

    class Config:
        orm_mode = True

class ScanCreate(BaseModel):
    sample_id: int

class ScanStatus(BaseModel):
    id: int
    status: str

    class Config:
        orm_mode = True

class ScanResult(BaseModel):
    id: int
    status: str
    result: str | None

    class Config:
        orm_mode = True

class RuleCreate(BaseModel):
    name: str

class RuleOut(BaseModel):
    id: int
    name: str
    path: str
    active: bool

    class Config:
        orm_mode = True
