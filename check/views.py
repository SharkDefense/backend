from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from .serializers import URLSerializer
from .features.screen import get_screenshot
from .features.graph import graph
from .features.ip_reputation import ip_reputation
from .features.whois import whois
from .machine_model.ml import predict
from rest_framework.permissions import AllowAny




@api_view(['POST'])
@permission_classes([AllowAny])
def test(request):
    if request.method == 'POST':
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            

            result={
                'url': url,
                'Classification_result': predict(url),
                'Graph visualization ':graph(url),
                'Screenshot':get_screenshot(url),
                'IP Reputation':ip_reputation(url),
                'Whois':whois(url),
            }

            return Response(result)
        return Response(serializer.errors, status=400)
    

