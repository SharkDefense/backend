# myapp/model_loader.py

import joblib
import warnings, joblib
warnings.filterwarnings('ignore')
import os

gbc = None

def initialize_model():
    global gbc
    model_path = os.environ.get("Model_path")
    try:
        gbc = joblib.load(model_path)
        print("Model loaded successfully.")
    except FileNotFoundError:
        print("The original model file was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
