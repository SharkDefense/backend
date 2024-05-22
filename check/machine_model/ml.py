from .feature import FeatureExtraction
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import joblib
warnings.filterwarnings('ignore')


def load_model():
    try:
        gbc = joblib.load(
            "K:\django projects\DPA\DPA\check\machine_model\model.pkl")
        print("Model loaded successfully.")
    except FileNotFoundError:
        print("The original model file was not found.")
        gbc = None  # تعيين gbc إلى None لمنع الأخطاء إذا حاولت استخدامه في تنبؤ
    except Exception as e:
        print(f"An error occurred: {e}")
        gbc = None

    return gbc


def predict(url):
    gbc = load_model()
    if gbc:
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        prediction_message = "It is safe" if y_pred == 1 else "It is not safe"
        return {
            'prediction': prediction_message,
            'phishing_probability': y_pro_phishing * 100,
            'non_phishing_probability': y_pro_non_phishing * 100,
        }
    else:
        return {'message': 'Model not loaded.'}
