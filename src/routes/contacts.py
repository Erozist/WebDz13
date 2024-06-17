from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from src.database.db import get_db
from src.schemas.schemas import ContactCreate, ContactUpdate, Contact as ContactSchema
import src.repository.contacts as crud
from src.utils.utils import get_current_user
from src.database.models import User

router = APIRouter(
    prefix="/contacts",
    tags=["contacts"]
)

@router.post("/", response_model=ContactSchema, status_code=201)
async def create_contact(contact: ContactCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await crud.create_contact(db=db, contact=contact, owner_id=current_user.id)

@router.get("/", response_model=List[ContactSchema])
async def read_contacts(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await crud.get_contacts(db=db, skip=skip, limit=limit, owner_id=current_user.id)

@router.get("/{contact_id}", response_model=ContactSchema)
async def read_contact(contact_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = await crud.get_contact(db, contact_id)
    if db_contact is None or db_contact.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.put("/{contact_id}", response_model=ContactSchema)
async def update_contact(contact_id: int, contact: ContactUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = await crud.update_contact(db, contact_id, contact, owner_id=current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.delete("/{contact_id}", response_model=ContactSchema)
async def delete_contact(contact_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = await crud.delete_contact(db, contact_id, owner_id=current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.get("/search/", response_model=List[ContactSchema])
async def search_contacts(query: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await crud.search_contacts(db=db, query=query, owner_id=current_user.id)

@router.get("/upcoming-birthdays/", response_model=List[ContactSchema])
async def upcoming_birthdays(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await crud.get_upcoming_birthdays(db=db, owner_id=current_user.id)
