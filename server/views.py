from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from django.http import FileResponse, Http404
import os
from .serializers import CustomUserSerializer, PageMasterSerializer, PostSerializer
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .models import CustomUser, UserCaja, PageMaster, CustomToken, Post
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail, EmailMessage
from dotenv import load_dotenv
from django.contrib.auth import get_user_model
from rest_framework import viewsets, permissions
from .authentication import PageMasterTokenAuthentication


from rest_framework.exceptions import PermissionDenied

load_dotenv()

email_recipient = os.getenv('EMAIL_RECIPIENT', 'recipient1@example.com').split(',')
email_sender = os.getenv('EMAIL_SENDER', 'sender@example.com')

ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg'}
ALLOWED_PLANILLA = {'docx'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@api_view(['POST'])
def login(request):
    user = get_object_or_404(CustomUser, email=request.data['email'])
    
    if not user.check_password(request.data['password']):
        return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)

    token, _ = Token.objects.get_or_create(user=user)
    serializer = CustomUserSerializer(instance=user)

    return Response({"token": token.key, "user": serializer.data}, status=status.HTTP_200_OK)

@api_view(['POST'])
def register(request):
    cedula = request.data.get('cedula')
    user_caja = UserCaja.objects.filter(CE_TRABAJADOR=cedula).first()
    
    if not user_caja:
        return Response({"error": "No esta registrado en la caja"}, status=status.HTTP_400_BAD_REQUEST)

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
        
        send_mail(
            'Password Reset Request',
            f'Use the link to reset your password: http://localhost:3000/auth/signin/password_reset/confirm?uid={uid}&token={token}',
            email_sender,
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
def upload_files(request):
    planilla = request.FILES.get('file6')
    expected_files = ['file', 'file2', 'file3', 'file4', 'file5']
    files = []

    for file_name in expected_files:
        file = request.FILES.getlist(file_name)
        if not file:
            return Response({"error": f"File '{file_name}' is required."}, status=status.HTTP_400_BAD_REQUEST)
        files.extend(file)

    if len(files) != len(expected_files):
        return Response({"error": "Todos los archivos son requeridos."}, status=status.HTTP_400_BAD_REQUEST)

    for file in files:
        if not allowed_file(file.name, ALLOWED_EXTENSIONS):
            return Response({"error": f"Archivo '{file.name}' no es valido, debe ser PDF o JPEG."}, status=status.HTTP_400_BAD_REQUEST)

    if not planilla or not allowed_file(planilla.name, ALLOWED_PLANILLA):
        return Response({"error": "The planilla must be in DOCX format."}, status=status.HTTP_400_BAD_REQUEST)

    subject = 'Solicitud de Inscripcion'
    message = ''
    email = EmailMessage(subject, message, email_sender, email_recipient)

    for index, file in enumerate(files):
        new_filename = f"{index + 1}_{file.name}"
        email.attach(new_filename, file.read(), file.content_type)

    planilla_new_name = f"planilla_{planilla.name}"
    email.attach(planilla_new_name, planilla.read(), planilla.content_type)

    try:
        email.send(fail_silently=False)
        return Response({"message": "Archivos enviados al correo"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": f"Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def download_docx(request):
    filename = 'planilla.docx'
    file_path = os.path.join('C:\\Users\\pc\\Desktop\\proyectos\\login-and-logout-api-\\server\\documento', filename)
    
    if not os.path.exists(file_path):
        raise Http404("El archivo no existe.")
    
    response = FileResponse(open(file_path, 'rb'), content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# PageMaster

@api_view(['POST'])
def pagemaster_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({"error": "Usuario y contraseña son requeridos."}, status=status.HTTP_400_BAD_REQUEST)

    User = get_user_model() 

    try:
        user = User.objects.get(username=username)

        if not user.check_password(password):
            return Response({"error": "Contraseña invalida"}, status=status.HTTP_400_BAD_REQUEST)

        token, created = CustomToken.objects.get_or_create(user=user)

        # Serialize user data
        serializer = PageMasterSerializer(instance=user)

        return Response({"token": token.key, "user": serializer.data}, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"Exception: {e}")  # Log the error to the console
        return Response({"error": "Ah ocurrido un error, por favor intentalo nuevamente."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['GET', 'POST'])
@authentication_classes([PageMasterTokenAuthentication])
def post_list_create(request):
    # GET: Everyone can see the posts
    if request.method == 'GET':
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    # POST: Only PageMasters can create posts
    if request.method == 'POST':
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@authentication_classes([PageMasterTokenAuthentication])
@permission_classes([IsAuthenticated])
def post_detail(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    if request.method == 'GET':
        serializer = PostSerializer(post)
        return Response(serializer.data)

    elif request.method in ['PUT', 'PATCH']:
        serializer = PostSerializer(post, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)