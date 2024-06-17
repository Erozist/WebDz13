import cloudinary
import cloudinary.uploader
from src.config.settings import settings

cloudinary.config(
    cloud_name=settings.cloudinary_name,
    api_key=settings.cloudinary_api_key,
    api_secret=settings.cloudinary_api_secret
)

def upload_image(file):
    result = cloudinary.uploader.upload(file)
    return result['secure_url']

