import requests
import json
from PIL import Image
import base64
from io import BytesIO
# Your PageSpeed Insights API endpoint
API_KEY = 'AIzaSyBEvMEs5sPH4ZJDIcv3fxtC1BGfHh1imnI'
PSI_API_URL = f'https://www.googleapis.com/pagespeedonline/v5/runPagespeed?key={API_KEY}'


def get_screenshot(url):
    params = {
        'url': url,
        'strategy': 'desktop',  # 'mobile' or 'desktop' based on your requirement
        'screenshot': True,
    }

    response = requests.get(PSI_API_URL, params=params)

    if response.status_code == 200:
        result = response.json()
        screenshot_data = result.get('lighthouseResult', {}).get('audits', {}).get('final-screenshot', {}).get(
            'details', {}).get('data', None)
        if screenshot_data:
            # Decode the base64 string to bytes

            # image_data = base64.b64decode(screenshot_data.split(',')[1])
            # img = Image.open(BytesIO(image_data))
            # img.show()
            return screenshot_data
        else:
            return 'Unable to fetch screenshot data'
    else:
        return ' API request failed'

# x=get_screenshot('https://www.google.com')
# print(x)

#https://viewmm.site/Tabdul.latheef@shamalgroup.ae

