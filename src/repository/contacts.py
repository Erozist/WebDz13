from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload
from src.database.models import Contact
from src.schemas.schemas import ContactCreate, ContactUpdate
from datetime import date, timedelta

async def get_contacts(db: AsyncSession, skip: int = 0, limit: int = 10, owner_id: int = 10):
    result = await db.execute(
        select(Contact).options(joinedload(Contact.owner)).where(Contact.owner_id == owner_id).offset(skip).limit(limit)
    )
    return result.scalars().all()

async def create_contact(db: AsyncSession, contact: ContactCreate, owner_id: int):
    db_contact = Contact(**contact.dict(), owner_id=owner_id)
    db.add(db_contact)
    await db.commit()
    await db.refresh(db_contact)
    return db_contact

async def get_contact(db: AsyncSession, contact_id: int):
    result = await db.execute(select(Contact).where(Contact.id == contact_id))
    return result.scalars().first()

async def update_contact(db: AsyncSession, contact_id: int, contact: ContactUpdate, owner_id: int):
    db_contact = await get_contact(db, contact_id)
    if db_contact is None or db_contact.owner_id != owner_id:
        return None
    for key, value in contact.dict().items():
        setattr(db_contact, key, value)
    db.add(db_contact)
    await db.commit()
    await db.refresh(db_contact)
    return db_contact

async def delete_contact(db: AsyncSession, contact_id: int, owner_id: int):
    db_contact = await get_contact(db, contact_id)
    if db_contact is None or db_contact.owner_id != owner_id:
        return None
    await db.delete(db_contact)
    await db.commit()
    return db_contact

async def search_contacts(db: AsyncSession, query: str, owner_id: int):
    result = await db.execute(
        select(Contact).options(joinedload(Contact.owner))
        .where(
            (Contact.owner_id == owner_id) &
            (
                Contact.first_name.contains(query) |
                Contact.last_name.contains(query) |
                Contact.email.contains(query)
            )
        )
    )
    return result.scalars().all()

async def get_upcoming_birthdays(db: AsyncSession, owner_id: int):
    today = date.today()
    next_week = today + timedelta(days=7)
    result = await db.execute(
        select(Contact).options(joinedload(Contact.owner))
        .where(
            (Contact.owner_id == owner_id) &
            (Contact.birthday >= today) &
            (Contact.birthday <= next_week)
        )
    )
    return result.scalars().all()
