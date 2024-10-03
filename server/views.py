from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import FileResponse, Http404
import os
from .serializers import CustomUserSerializer
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .models import CustomUser, UserCaja  
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.core.mail import send_mail, EmailMessage
from dotenv import load_dotenv

load_dotenv()


ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg'}  # Add 'docx' for Word files
ALLOWED_PLANILLA = {'docx'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_planilla(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PLANILLA


@api_view(['POST'])
def login(request):
    user = get_object_or_404(CustomUser, email=request.data['email'])

    if not user.check_password(request.data['password']):
        return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)

    token, created = Token.objects.get_or_create(user=user)
    serializer = CustomUserSerializer(instance=user)

    return Response({"token": token.key, "user": serializer.data}, status=status.HTTP_200_OK)

@api_view(['POST'])
def register(request):
    cedula = request.data.get('cedula')

    user_caja = UserCaja.objects.filter(CE_TRABAJADOR=cedula).first()
    if not user_caja:
        return Response({"error": "No esta registrado en la caja"}, status=status.HTTP_400_BAD_REQUEST)

    # Proceed with user registration
    serializer = CustomUserSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()
        user.set_password(request.data['password'])
        user.save()

        token = Token.objects.create(user=user)
        return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def password_reset(request):
    email = request.data.get('email')
    if not email:
        return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Send email with the reset link
        send_mail(
            'Password Reset Request',
            f'Use the link to reset your password: http://localhost:3000/auth/signin/password_reset/confirm?uid={uid}&token={token}',
            'from@example.com',  # Replace with your sender email
            [email],
            fail_silently=False,
        )
        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def password_reset_confirm(request):
    uid = request.data.get('uid')
    token = request.data.get('token')
    new_password = request.data.get('new_password')

    if not all([uid, token, new_password]):
        return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user_id = urlsafe_base64_decode(uid).decode()
        user = CustomUser.objects.get(pk=user_id)

        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password has been reset."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
    except (CustomUser.DoesNotExist, ValueError):
        return Response({"error": "Invalid user."}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def profile(request):
    serializer = CustomUserSerializer(instance=request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
# @authentication_classes([TokenAuthentication])
# @permission_classes([IsAuthenticated])
def upload_files(request):
    # files = request.FILES.getlist('files')  # Get the list of uploaded files
    planilla = request.FILES.get('file6')  # Get the planilla file
    expected_files = ['file', 'file2', 'file3', 'file4', 'file5']
    files = []

    # Validate file types for the five files
    for file_name in expected_files:

        file = request.FILES.getlist(file_name)

        if file:
            # files.append(file)
            files.extend(file)
        else:
            return Response({"error": f"El archivo : {file_name} , Es requerido."}, status=status.HTTP_400_BAD_REQUEST)


    # Validate number of files
    if len(files) != len(expected_files):
        return Response({"error": "Todos los archivos son requeridos."}, status=status.HTTP_400_BAD_REQUEST)

    for file in files:
          if not allowed_file(file.name):
            return Response({"error": f"Archivo '{file.name}' no es valido, debe ser PDF o JPEG."}, status=status.HTTP_400_BAD_REQUEST)
    
    # Validate planilla file type
    if planilla is None or not allowed_planilla(planilla.name) or planilla.name.rsplit('.', 1)[1].lower() != 'docx':
        return Response({"error": "La planilla debe ser en formato (DOCX)."}, status=status.HTTP_400_BAD_REQUEST)

    # Prepare email
    user = request.data.get("full_name")  # Get the authenticated user
    # full_name = f"{user.full_name}"
   
    subject = f'Solicitud de Inscripcion'
    message = ''
    email = EmailMessage(subject, message, os.getenv('EMAIL_SENDER', 'your_email@example.com') , os.getenv('EMAIL_RECIPIENT', 'your_email@example.com') )

    # Attach the five files to the email
    for file in files:
        email.attach(file.name, file.read(), file.content_type)

    # Attach the planilla file to the email
    email.attach(planilla.name, planilla.read(), planilla.content_type)

    # Send email
    try:
        email.send(fail_silently=False)
        return Response({"message": "Archivos enviados al correo"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": f"Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
def download_docx(request):
    # Define la ruta del archivo
    filename = 'planilla.docx'
    file_path = os.path.join('C:\\Users\\pc\\Desktop\\proyectos\\login-and-logout-api-\\server\\documento', filename)
    
    # Verifica si el archivo existe
    if not os.path.exists(file_path):
        raise Http404("El archivo no existe.")
    
    # Devuelve el archivo como respuesta
    with open(file_path, 'rb') as doc_file:
        response = FileResponse(open(file_path, 'rb'), content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response   
