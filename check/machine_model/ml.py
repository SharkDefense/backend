import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings, joblib
warnings.filterwarnings('ignore')
from .feature import FeatureExtraction
import os


def load_model():
    try:
        gbc = joblib.load(os.environ.get("Model_path")) 
        print("Model loaded successfully.")
    except FileNotFoundError:
        print("The original model file was not found.")
        gbc = None  # تعيين gbc إلى None لمنع الأخطاء إذا حاولت استخدامه في تنبؤ
    except Exception as e:
        print(f"An error occurred: {e}")
        gbc=None

    return gbc




def predict(url):
    gbc=load_model()
    if gbc:
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]

        prediction_message = "It is safe" if y_pred == 1 else "malicious from model"
        return  prediction_message
        
    else:
        return {'message': 'Model not loaded.'}

