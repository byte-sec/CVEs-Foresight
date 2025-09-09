import customtkinter as ctk
import threading

# Initialize logging first
from logging_config import setup_logging
setup_logging()

import database

# Initialize database (no thread needed with new system)
database.setup_database()

# Import after database setup
from backend import api_handler as backend
from gui.main_window import App

if __name__ == "__main__":
    # Set the appearance mode and default color theme
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    # Create and run the application
    app = App()
    app.mainloop()