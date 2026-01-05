

from langchain_google_genai import ChatGoogleGenerativeAI
from app.config import settings


class Models:
    def __init__(self):
        self.gemini = self.load_gemini()
   
    def load_gemini(self):
        return ChatGoogleGenerativeAI(
            model="gemini-2.0-flash", temperature=0, api_key=settings.GEMINI_API_KEY
        )

    @property
    def GEMINI(self):
        return self.gemini
        


models = Models()
