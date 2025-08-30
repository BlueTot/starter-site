import sys
import os
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(__file__))

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

from backend.app import application
