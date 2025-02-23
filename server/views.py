from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from django.http import FileResponse, Http404
import os
from .serializers import CustomUserSerializer, PageMasterSerializer, PostSerializer,InnerPrestamoSerializer,FileUploadSerializer  
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .models import CustomUser, UserCaja, PageMaster, Post
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail, EmailMessage
from dotenv import load_dotenv
from django.contrib.auth import get_user_model
from rest_framework import viewsets, permissions
from rest_framework.permissions import AllowAny
import logging
from .permissions import IsPageMaster, IsCustomUser 
from django.utils import timezone
from rest_framework.pagination import PageNumberPagination
from django.db import connections
from django.contrib.auth.models import Group
from .models import InnerPrestamo
import logging

import pandas as pd
from django.core.management.base import BaseCommand
from server.models import UserCaja  #
from django.core.exceptions import ValidationError

from django.http import JsonResponse
from django.db import transaction
from .models import FileUpload 
from django.shortcuts import render
from .helpers import verificar_eligibilidad_prestamo  


MAX_FILE_SIZE = 80 * 1024 * 1024  # 80 MB



logger = logging.getLogger(__name__)


from rest_framework.exceptions import PermissionDenied

load_dotenv()

email_recipient = os.getenv('EMAIL_RECIPIENT', 'recipient1@example.com').split(',')
email_sender = os.getenv('EMAIL_SENDER', 'sender@example.com')
front = os.getenv('FRONT_URL', 'http://localhost:3000')

ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg'}
ALLOWED_PLANILLA = {'docx'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email y contraseña son requeridos."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)

        if not user.check_password(password):
            return Response({"error": "Contraseña invalida"}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the user has the CustomUser role
        custom_user_group, _ = Group.objects.get_or_create(name='CustomUser')
        if custom_user_group not in user.groups.all():
            user.groups.add(custom_user_group)

        # Token management
        Token.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)

        serializer = CustomUserSerializer(instance=user)
        return Response({"token": token.key, "user": serializer.data}, status=status.HTTP_200_OK)

    except CustomUser.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"Exception: {e}")
        return Response({"error": "Ha ocurrido un error, por favor intentalo nuevamente."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




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

        # Assign user to the CustomUser group
        custom_user_group, _ = Group.objects.get_or_create(name='CustomUser')
        user.groups.add(custom_user_group)

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
            f'Usa este link para cambiar tus credenciales: {front}/auth/signin/password_reset/confirm?uid={uid}&token={token}',
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
@permission_classes([IsCustomUser])
def profile(request):
    serializer = CustomUserSerializer(instance=request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['PUT'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def update_own_profile(request):
    custom_user = request.user 
    
    if 'cedula' in request.data:
        return Response({"error": "No se puede cambiar la cedula."}, status=status.HTTP_400_BAD_REQUEST)

    serializer = CustomUserSerializer(custom_user, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()  # Save the updated user details
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






    # Extract values from the request data


logger = logging.getLogger(__name__)

def get_int_param(data, param_name, default=None):
    """Helper function to safely get an integer parameter from the request."""
    value = data.get(param_name)
    if value is None:
        if default is not None:
            return default
        raise ValueError(f"'{param_name}' is required and cannot be None.")
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"'{param_name}' should be an integer.")

logger = logging.getLogger(__name__)

def get_int_param(data, param_name, default=None):
    """Helper function to safely get an integer parameter from the request."""
    value = data.get(param_name)
    if value is None:
        if default is not None:
            return default
        raise ValueError(f"'{param_name}' is required and cannot be None.")
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"'{param_name}' should be an integer.")
    

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def create_loan_request(request):
    try:
        # First, check if files are present
        if request.FILES.getlist('files'):
            files = request.FILES.getlist('files')

            # Calculate the total size of all the files
            total_size = sum(file.size for file in files)

            # Check if the total size exceeds the maximum limit (80MB)
            if total_size > MAX_FILE_SIZE:
                return JsonResponse({'error': f'Total file size exceeds the maximum allowed size of 80MB.'}, status=400)

        # Extract necessary data from the request (cedulasoc and codptmo)
        cedulasoc = int(request.user.cedula)
        codptmo = request.data.get('codptmo')

        # Call the helper function to check loan eligibility
        resultado = verificar_eligibilidad_prestamo(cedulasoc, codptmo)
        
        # If there's an error in the eligibility check, return the error response
        if 'error' in resultado:
            return JsonResponse({'error': resultado['error']}, status=400)

        # If the eligibility check passes, proceed with creating the loan
        # Parameters for the stored procedure (should come from the request)
        ncuotas = request.data.get('ncuotas') 
        monto = request.data.get('monto') 
        garantia = request.data.get('garantia', 0)  # Default to 1 if not provided
        cuotaespecial = request.data.get('cuotaespecial', 0)  # Default to 0 if not provided
        modalidad = request.data.get('modalidad', 0)  # Default to 1 if not provided
        cifiador1 = request.data.get('cifiador1', 0)  # Default to 0 if not provided
        cifiador2 = request.data.get('cifiador2', 0)  # Default to 0 if not provided
        cifiador3 = request.data.get('cifiador3', 0)  # Default to 0 if not provided
        cifiador4 = request.data.get('cifiador4', 0)  # Default to 0 if not provided

        # SQL query to execute the stored procedure and capture the OUTPUT serial
        sp_query = """
            DECLARE @serial INT;
            EXEC [dbo].[sp_CreaSolicitudPtmo] 
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, @serial OUTPUT;
            SELECT @serial AS serial;
        """
        
        with connections['sqlserver'].cursor() as cursor:
            cursor.execute(sp_query, [
                cedulasoc, codptmo, ncuotas, monto, garantia, cuotaespecial, 
                modalidad, cifiador1, cifiador2, cifiador3, cifiador4
            ])
            # Fetch the output (serial)
            row = cursor.fetchone()
            serial = row[0] if row else None

        # After executing the stored procedure, check if serial is valid
        if serial:
            # Check if files were uploaded and their total size
            if request.FILES.getlist('files'):
                files = request.FILES.getlist('files')

                # Calculate the total size of all the files
                total_size = sum(file.size for file in files)

                # Check if the total size exceeds the maximum limit (80MB)
                if total_size > MAX_FILE_SIZE:
                    return JsonResponse({'error': f'Total file size exceeds the maximum allowed size of 80MB.'}, status=400)

                # Create the FileUpload model with the provided serial
                file_upload = FileUpload(serial=serial)
                file_upload.save()  # Save the model to generate the directory

                # Now create files in the specified directory
                file_upload.create_files(files)

            return JsonResponse({
                'message': 'Préstamo creado exitosamente',
                'serial': serial  # Include the generated serial in the response
            }, status=200)
        else:
            # If serial is None, return a failure message
            return JsonResponse({'error': 'No se pudo crear el préstamo, intente de nuevo.'}, status=500)

    except Exception as e:
        # Handle any exceptions (e.g., database errors) and return a failure response
        return JsonResponse({'error': str(e)}, status=500)



    
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def verify_loan(request):
    if request.method == 'POST':
        cedula = int(request.user.cedula)
        
        # Log the incoming request data to inspect
        print(f"Request Data: {request.data}")  # For JSON requests
        print(f"Request POST: {request.POST}")  # For form requests

        cod_prestamo = request.data.get('codptmo')  # Use .get for safety

        print(f"COD_PRESTAMO: {cod_prestamo}")

        # Llamamos al helper para verificar si el socio es elegible
        resultado = verificar_eligibilidad_prestamo(cedula, cod_prestamo)

        # Comprobamos si hay un error
        if 'error' in resultado:
            return JsonResponse({'error': resultado['error']}, status=400)

        # Si no hay error, el socio puede solicitar el préstamo
        return JsonResponse({'message': resultado['message']}, status=200)



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


        Token.objects.filter(user=user).delete()

        token = Token.objects.create(user=user)
        serializer = PageMasterSerializer(instance=user)

        return Response({"token": token.key, "user": serializer.data}, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"Exception: {e}") 
        return Response({"error": "Ah ocurrido un error, por favor intentalo nuevamente."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class PostPagination(PageNumberPagination):
    page_size = 9
    page_size_query_param = 'page_size'
    max_page_size = 100


@api_view(['GET'])
def post_list(request):
    posts = Post.objects.all().order_by('-updated_at')
    
    paginator = PostPagination()
    paginated_posts = paginator.paginate_queryset(posts, request)

    serializer = PostSerializer(paginated_posts, many=True)

    response_data = {
        'total_posts': posts.count(),
        'total_pages': paginator.page.paginator.num_pages,
        'results': serializer.data,
    }

    return paginator.get_paginated_response(response_data)


@api_view(['POST'])
@permission_classes([IsPageMaster])
def post_create(request):
    logger.debug(f"Incoming data: {request.data}")  
    serializer = PostSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.debug(f"Post created: {serializer.data}")
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    logger.error(f"Validation errors: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def post_detail_get(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    serializer = PostSerializer(post)
    return Response(serializer.data)

@api_view(['PUT', 'PATCH', 'DELETE'])
@permission_classes([IsPageMaster])
def post_detail_modify(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    if request.method in ['PUT', 'PATCH']:
        serializer = PostSerializer(post, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def ping(request):
    token = Token.objects.get(user=request.user)
    token.created = timezone.now()  
    token.save()  
    
    return Response({"message": "Pong!", "token_expiration_updated": True}, status=status.HTTP_200_OK)


class CustomUserPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

@api_view(['GET'])
@permission_classes([IsPageMaster])
def search_custom_users(request):
    cedula = request.query_params.get('cedula', None)
    full_name = request.query_params.get('full_name', None)

    filters = {}

    if cedula:
        filters['cedula__icontains'] = cedula

    if full_name:
        filters['full_name__icontains'] = full_name

    # Adjust query to exclude users with null phone_number and empty full_name
    custom_users = CustomUser.objects.exclude(phone_number__isnull=True, full_name="").filter(**filters)

    total_custom_users = custom_users.count()

    paginator = CustomUserPagination()
    paginated_users = paginator.paginate_queryset(custom_users, request)

    serializer = CustomUserSerializer(paginated_users, many=True)

    response_data = {
        'total_custom_users': total_custom_users,
        'total_pages': paginator.page.paginator.num_pages,
        'results': serializer.data,
    }

    return Response(response_data, status=status.HTTP_200_OK)

@api_view(['PUT'])
@permission_classes([IsPageMaster])
def update_custom_user(request, custom_user_id):
    """
    Allows a PageMaster to update the properties of a CustomUser given their ID.
    """
    custom_user = get_object_or_404(CustomUser, id=custom_user_id)
    
    serializer = CustomUserSerializer(custom_user, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()  
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class InnerPrestamoPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100
    page_query_param = 'page'

@api_view(['GET'])
@permission_classes([IsPageMaster])
def search_inner_prestamos(request):
    # Get query parameters from request
    name = request.query_params.get('name', None)
    
    # Create filter dictionary
    filters = {}
    if name:
        filters['name__icontains'] = name

    # Get and filter queryset with ID ordering
    inner_prestamos = InnerPrestamo.objects.filter(**filters).order_by('id')  # Changed to 'id'
    
    # Paginate results
    paginator = InnerPrestamoPagination()
    paginated_queryset = paginator.paginate_queryset(inner_prestamos, request)
    
    # Serialize data
    serializer = InnerPrestamoSerializer(paginated_queryset, many=True)
    
    return Response({
        'total_inner_prestamos': inner_prestamos.count(),
        'total_pages': paginator.page.paginator.num_pages,
        'results': serializer.data
    })

# SQL REQUESTS  

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def user_loans(request):
    cedula = request.user.cedula  

    query = """
SELECT
    S.SERIAL,
    S.CODPTMO,
    P.DESCRIP,
    S.FECOTORG,
    S.FECPPAG,
    S.FECULTPAG,
    S.FECULTCUO,
    S.NROCUOTA,
    S.NCP,
    S.MONTOCUOTA,
    S.MONTO,
    S.TASA,
    S.SALDO,
    S.STATUS,
    S.CUOTA1,
    S.SALDO1,
    S.CUOTA2,
    S.SALDO2
FROM PRESOCIO S
INNER JOIN PRESTAMO P ON P.CODPTMO = S.CODPTMO
WHERE S.CEDSOC = %s AND S.SALDO > 0
    """

    with connections['sqlserver'].cursor() as cursor:
        cursor.execute(query, [cedula])
        rows = cursor.fetchall()

    results = [
        {
            'SERIAL': row[0],
            'CODPTMO': row[1],
            'DESCRIP': row[2],
            'FECOTORG': row[3],
            'FECPPAG': row[4],
            'FECULTPAG': row[5],
            'FECULTCUO': row[6],
            'NROCUOTA': row[7],
            'NCP': row[8],
            'MONTOCUOTA': row[9],
            'MONTO': row[10],
            'TASA': row[11],
            'SALDO': row[12],
            'STATUS': row[13],
            'CUOTA1': row[14],
            'SALDO1': row[15],
            'CUOTA2': row[16],
            'SALDO2': row[17],
        }
        for row in rows
    ]

    return Response(results, status=status.HTTP_200_OK)



@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def haberes(request):
    cedula = request.user.cedula  

    query = """
        ;WITH
        -- Step 1: Calculate the 'Agravados' sum
        Agravados AS (
            SELECT SUM(SALDO) AS TotalAgravado
            FROM PRESOCIO
            WHERE CEDSOC = %s 
              AND GrabaAhorro = 1
            GROUP BY CEDSOC
        ),
        -- Step 2: Calculate the 'Disponibilidad'
        Disponibilidad AS (
            SELECT SUM(SALDOAHO - SALDOBLOQ) AS TotalDisponibilidad
            FROM AHOSOCIO
            WHERE CEDSOC = %s 
              AND CODAHO IN (98, 99)
            GROUP BY CEDSOC
        ),
        -- Step 3: Get the total embargos
        Embargos AS (
            SELECT [oca20].[dbo].[fn_Embargos](%s) AS TotalEmbargos
        ),
        -- Step 4: Calculate the haberes (same as 'Disponibilidad')
        Haberes AS (
            SELECT SUM(SALDOAHO - SALDOBLOQ) AS TotalHaberes
            FROM AHOSOCIO
            WHERE CEDSOC = %s 
              AND CODAHO IN (98, 99)
            GROUP BY CEDSOC
        ),
        -- Step 5: Retrieve the sueldo from SOCIOS
        Sueldo AS (
            SELECT SUELDO
            FROM dbo.SOCIOS
            WHERE CEDSOC = %s
        )
        -- Final Calculation
        SELECT 
            Agravados.TotalAgravado,
            Disponibilidad.TotalDisponibilidad,
            (Disponibilidad.TotalDisponibilidad / 2) AS Disponibilidad50,
            Embargos.TotalEmbargos,
            Haberes.TotalHaberes,
            (Disponibilidad.TotalDisponibilidad / 2) - Embargos.TotalEmbargos AS FinalSaldo,
            Sueldo.SUELDO
        FROM 
            Agravados
            CROSS JOIN Disponibilidad
            CROSS JOIN Embargos
            CROSS JOIN Haberes
            CROSS JOIN Sueldo;
    """

    # Execute the query
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute(query, [cedula, cedula, cedula, cedula, cedula])  
        row = cursor.fetchone()

    # Format the result
    if row:
        result = [
            {
                "Total_Agravados": row[0] if row[0] is not None else 0,  # Ensure no null value
                "Disponibilidad": row[1] if row[1] is not None else 0,  # Ensure no null value
                "50_Porcentaje_Disponibilidad": row[2] if row[2] is not None else 0,  # Ensure no null value
                "Total_Embargos": row[3] if row[3] is not None else 0,  # Ensure no null value
                "Saldo_Final": row[4] if row[4] is not None else 0,  # Ensure no null value
                "Sueldo": row[5] if row[5] is not None else 0  # Ensure no null value for SUELDO
            }
        ]
    else:
        result = []

    return Response(result, status=status.HTTP_200_OK)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def dividendos(request):
    cedula = request.user.cedula  # Get the user's cedula from the authenticated user

    query = """
        -- Step 1: Retrieve dividendos data from AHOSOCIO and AHORROS
        SELECT 
            S.CODAHO,
            A.DESCRIP,
            S.SALDOAHO
        FROM 
            AHOSOCIO S 
        INNER JOIN 
            AHORROS A ON A.CODAHO = S.CODAHO
        WHERE 
            S.CEDSOC = %s
    """

    # Execute the query
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute(query, [cedula])  # Pass cedula for the placeholder
        rows = cursor.fetchall()

    # Format the result
    result = []
    if rows:
        for row in rows:
            result.append({
                "Codigo_Ahorro": row[0] if row[0] is not None else 0,  # Renamed to 'Codigo Ahorro'
                "Descripcion": row[1] if row[1] is not None else "",  # Ensure no null value for DESCRIP
                "Saldo_Ahorro": row[2] if row[2] is not None else 0  # Ensure no null value for SALDOAHO
            })
    
    return Response(result, status=status.HTTP_200_OK)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def solicitudes(request):
    cedula = request.user.cedula  # Get the user's cedula from the authenticated user

    query = """
        -- Step 1: Retrieve solicitudes data from SOLICITUD, SOCIOS, and PRESTAMO
        SELECT
            dbo.SOLICITUD.SERIAL,
            dbo.SOCIOS.APELLIDOS,
            dbo.SOCIOS.NOMBRE,
            dbo.SOLICITUD.MONTOSOLI,
            dbo.SOLICITUD.MONTOPTMO,
            dbo.SOLICITUD.WEB,
            dbo.SOLICITUD.CUOESP,
            dbo.PRESTAMO.DESCRIP,
            dbo.SOLICITUD.NROCUOTA,
            dbo.SOLICITUD.TASA,
            dbo.SOLICITUD.STATUS,
            dbo.SOLICITUD.NRODOC,
            dbo.SOLICITUD.EMITIDO,
            dbo.SOLICITUD.CEDSOC
        FROM
            dbo.SOLICITUD
        INNER JOIN dbo.SOCIOS ON dbo.SOLICITUD.CEDSOC = dbo.SOCIOS.CEDSOC
        INNER JOIN dbo.PRESTAMO ON dbo.PRESTAMO.CODPTMO = dbo.SOLICITUD.CODPTMO
        WHERE
            dbo.SOLICITUD.CEDSOC = %s
            AND dbo.SOLICITUD.STATUS IN (1, 2, 3)
            AND dbo.SOLICITUD.EMITIDO = 0
            AND dbo.SOLICITUD.NRODOC = 0
    """

    # Execute the query
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute(query, [cedula])  # Pass cedula for the placeholder
        rows = cursor.fetchall()

    # Format the result
    result = []
    if rows:
        for row in rows:
            result.append({
                "Serial": row[0] if row[0] is not None else 0,
                "Apellidos": row[1] if row[1] is not None else "",
                "Nombre": row[2] if row[2] is not None else "",
                "Monto_Solicitado": row[3] if row[3] is not None else 0,
                "Monto_Prestamo": row[4] if row[4] is not None else 0,
                "Web": row[5] if row[5] is not None else "",
                "Cuotas_Esp": row[6] if row[6] is not None else 0,
                "Descripcion": row[7] if row[7] is not None else "",
                "Numero_Cuotas": row[8] if row[8] is not None else 0,
                "Tasa": row[9] if row[9] is not None else 0,
                "Status": row[10] if row[10] is not None else 0,
                "Numero_Documento": row[11] if row[11] is not None else 0,
                "Emitido": row[12] if row[12] is not None else 0,
                "Cedula_Socio": row[13] if row[13] is not None else ""
            })

    return Response(result, status=status.HTTP_200_OK)




@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def fianza(request):
    cedula = request.user.cedula  # Get the user's cedula from the authenticated user

    query = """
        SELECT [CEDFIA], [CEDSOC], dbo.fn_nombre([CEDSOC]) AS NOMBRESOCIO,
               [SALDO], P.DESCRIP,
               REPLACE(CONVERT(NVARCHAR, dbo.fn_datefromclarion([FECINI]), 106), ' ', '/') AS DESDE,
               REPLACE(CONVERT(NVARCHAR, dbo.fn_datefromclarion([FECFIN]), 106), ' ', '/') AS HASTA
        FROM [dbo].[FianzasActivas] V
        INNER JOIN PRESTAMO P ON V.CODPTMO = P.CODPTMO
        WHERE V.CEDFIA = %s
    """
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute(query, [cedula])  # Use cedula in the WHERE clause
        rows = cursor.fetchall()

    # Format the results
    result = [
        {
            "CEDFIA": row[0],
            "CEDSOC": row[1],
            "NOMBRESOCIO": row[2],
            "SALDO": row[3],
            "DESCRIP": row[4],
            "DESDE": row[5],
            "HASTA": row[6]
        }
        for row in rows
    ]

    return Response(result, status=status.HTTP_200_OK)


# pagemaster last function

EXPECTED_COLUMNS = [
    'CE_TRABAJADOR'
]

@api_view(['POST'])
@permission_classes([IsPageMaster])
def import_users_from_excel(request):
    
    if 'file' not in request.FILES:
        return JsonResponse({'detail': 'No file provided.'}, status=400)

    excel_file = request.FILES['file']
    
    try:
        df = pd.read_excel(excel_file)
        
        required_columns = ['CE_TRABAJADOR']
        
        if not all(col in df.columns for col in required_columns):
            return JsonResponse({'detail': 'Debe poseer las siguientes columnas: CE_TRABAJADOR.'}, status=400)
        
        with transaction.atomic():  
            UserCaja.objects.all().delete()  

            users = [
                UserCaja(
                    CE_TRABAJADOR=row['CE_TRABAJADOR']
                )
                for _, row in df.iterrows()
            ]
            
            # Perform the bulk insert
            UserCaja.objects.bulk_create(users)

        return JsonResponse({'detail': 'importacion Exitosa.'}, status=200)

    except Exception as e:
        return JsonResponse({'detail': f'Error importing users: {str(e)}'}, status=500)

from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from .models import InnerPrestamo
from django.db import connections
from .permissions import IsPageMaster

@api_view(['POST'])
@permission_classes([IsPageMaster])
def import_prestamos(request):
    # SQL query to fetch data from SQL Server
    query = """
        SELECT TOP (1000) 
               [CODPTMO], [CODART], [DESCRIP], [CIGLAS], [GRPPRE], [GRAHORRO], 
               [DEMPRE], [RECPRE], [CODLUZ], [PLAZOGRAHAB], [TIPCALINT], 
               [ANTIGUEDAD], [FIADOR], [PLAZOG], [REFINANCIA], [FRECUENCIA], 
               [ESTADO], [ENTPAR], [ORDDENAGENDA], [CUENTACO], [CUECON1], 
               [CUECON2], [MINCUOPAGO], [TIPO], [OBSERVACION], [PNPTMO], 
               [CUECON3], [AF1], [AF2], [AF3], [AF4], [AUX1], [AUX2], [AUX3], 
               [AUX4], [ACT_WEB], [AproAuto], [CartaCompromiso], 
               [LimiteMontoAfin], [GarantiaPrestaciones], [PermiteGrabarAhorro], 
               [CapacidadPago], [IMG_PRE], [Fiador2], [DESC2], [FianzaCrusada]
        FROM [oca20].[dbo].[PRESTAMO]
    """
    
    # Execute the SQL query to fetch the data from SQL Server
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()

    # Create a set of all prestamo IDs (CODPTMO) from the SQL result
    prestamo_ids_from_sql = {row[0] for row in rows}

    # Initialize counters for created and deleted records
    created_count = 0
    deleted_count = 0

    # Get the existing InnerPrestamos before creating new ones to avoid accidentally deleting newly created ones
    existing_inner_prestamos = {inner_prestamo.prestamo_id for inner_prestamo in InnerPrestamo.objects.all()}

    # Loop through the fetched data and check if InnerPrestamo exists in the SQLite database
    for row in rows:
        prestamo_id = row[0]  # Assuming the 'CODPTMO' is the first column, which is the prestamo ID
        prestamo_name = row[2]  # 'DESCRIP' is the third column

        # Check if there is an existing InnerPrestamo with the same 'prestamo_id'
        if prestamo_id not in existing_inner_prestamos:
            # If it doesn't exist, create a new InnerPrestamo
            InnerPrestamo.objects.create(
                prestamo_id=prestamo_id,  # Set 'prestamo_id' field to 'CODPTMO'
                name=prestamo_name,  # Set 'name' field to 'DESCRIP'
                description='',  # Set description as blank
                enable=False  # Set enable as False
            )
            created_count += 1  # Increment created count
        else:
            # Update the existing InnerPrestamo if the name is not already set correctly
            InnerPrestamo.objects.filter(prestamo_id=prestamo_id).update(name=prestamo_name)
    
    # Now, delete any InnerPrestamo that doesn't exist in the fetched prestamo_ids_from_sql
    for inner_prestamo in InnerPrestamo.objects.filter(prestamo_id__in=existing_inner_prestamos):
        if inner_prestamo.prestamo_id not in prestamo_ids_from_sql:
            # Delete InnerPrestamo if its 'prestamo_id' doesn't exist in the SQL Server data
            inner_prestamo.delete()
            deleted_count += 1  # Increment deleted count

    # Return a success response with the counts of created and deleted records
    return Response({
        'message': f'{created_count} InnerPrestamos created and {deleted_count} outdated InnerPrestamos deleted.'
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsPageMaster])  # Assuming IsPageMaster is a custom permission
def update_inner_prestamo(request):
    # Get 'prestamo_id' and the fields to update from the request body
    prestamo_id = request.data.get('prestamo_id')
    new_name = request.data.get('name')
    new_description = request.data.get('description', '')  # Optional, default to empty string
    new_enable = request.data.get('enable', False)  # Optional, default to False
    
    # Validate that the 'prestamo_id' was provided
    if not prestamo_id:
        return Response({'error': 'prestamo_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the InnerPrestamo exists
    inner_prestamo = InnerPrestamo.objects.filter(prestamo_id=prestamo_id).first()
    if not inner_prestamo:
        return Response({'error': 'InnerPrestamo with the given prestamo_id does not exist.'}, status=status.HTTP_404_NOT_FOUND)

    # Update the fields if they are provided
    if new_name:
        inner_prestamo.name = new_name
    if new_description:
        inner_prestamo.description = new_description
    if new_enable is not None:  # Only update if the value is explicitly provided
        inner_prestamo.enable = new_enable

    # Save the updated InnerPrestamo
    inner_prestamo.save()

    # Return a success response with updated data
    return Response({
        'message': 'InnerPrestamo updated successfully.',
        'prestamo_id': inner_prestamo.prestamo_id,
        'name': inner_prestamo.name,
        'description': inner_prestamo.description,
        'enable': inner_prestamo.enable,
    }, status=status.HTTP_200_OK)

####################################


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsCustomUser])
def get_loan_options(request):
    cedula = request.user.cedula
    nombres = request.user.full_name
    
    if not cedula:
        return Response({"success": False, "message": "Cedula is required"}, status=400)
    
    # Step 1: Fetch savings details based on cedula
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute("""
            SELECT S.CODAHO, A.DESCRIP, S.SALDOAHO
            FROM oca20.dbo.AHOSOCIO S
            INNER JOIN AHORROS A ON A.CODAHO = S.CODAHO
            WHERE S.CEDSOC = %s AND (S.CODAHO = 98 OR S.CODAHO = 99)
        """, [cedula])
        
        savings_data = cursor.fetchall()
        total_savings = sum(row[2] for row in savings_data)
        savings_descriptions = [row[1] for row in savings_data]  # Extracting descriptions of savings
        savings_amounts = [row[2] for row in savings_data]  # Extracting amounts of savings

    # Step 2: Fetch available loans
    with connections['sqlserver'].cursor() as cursor:
        cursor.execute("SELECT * FROM PRESTAMO WHERE ESTADO = 'A' AND ACT_WEB = 1")
        loans = cursor.fetchall()

    loan_options = []
    for loan in loans:
        loan_data = {
            "loan_id": loan[0],  # Assuming loan ID is in the first column
            "description": f"{loan[1]} {loan[2]}",  # Assuming description is in the second and third columns
            "img_url": f"assets/images/prestamos/{loan[4]}.png",  # Assuming image is in the 5th column
            "codprestamo": loan[0],  # Loan code (same as loan ID)
            "ncuotas": [1, 2],  # Possible cuotas (installments)
            "recaudos": [],
            "max_amount": 0,
            "savings_details": [],
            "garantia": loan[5] if len(loan) > 5 else None,  # Assuming guarantee data is available in column 5
            "serial": loan[6] if len(loan) > 6 else None,  # Assuming serial is available in column 6
        }

        # Step 3: Calculate the maximum loan amount
        if loan[0] == 1:  # Example: for loan with CODPTMO = 1
            loan_data["max_amount"] = float(total_savings) * 0.5  # Convert total_savings to float
        elif loan[0] == 2 or loan[0] == 18:  # Loans based on specific savings types
            loan_data["max_amount"] = float(total_savings) * 0.8  # Convert total_savings to float
        else:
            loan_data["max_amount"] = float(total_savings)  # Default to the total savings as float

        # Add savings details (descriptions and amounts) to the loan data
        for desc, amt in zip(savings_descriptions, savings_amounts):
            loan_data["savings_details"].append({
                "description": desc,  # Savings description
                "amount": float(amt),  # Convert amount to float
            })

        # Step 4: Fetch related document requirements (recaudos)
        with connections['sqlserver'].cursor() as cursor:
            cursor.execute("SELECT * FROM RECAPRES WHERE CODPTMO = %s", [loan[0]])
            recaudos = cursor.fetchall()
            for recaudo in recaudos:
                loan_data["recaudos"].append({
                    "document": recaudo[1],  # Assuming document name is in second column
                    "optional": "Optional" if recaudo[2] == '1' else "Required"  # Assuming optional flag is in third column
                })

        loan_options.append(loan_data)

    # Step 5: Return the loan options in a JSON response
    return Response({
        "success": True,
        "message": "Loan options fetched successfully",
        "data": loan_options
    })



# file upload

def upload_files(request):
    if request.method == 'POST' and request.FILES.getlist('files'):
        try:
            # Retrieve the serial from the form data (not from request.data)
            serial = request.POST.get('serial')  # Use `request.POST.get()` for form fields
            
            # If no serial is provided, raise an error
            if not serial:
                return JsonResponse({'error': 'Serial is required.'}, status=400)

            # Get the uploaded files
            files = request.FILES.getlist('files')

            # Calculate the total size of all the files
            total_size = sum(file.size for file in files)

            # Check if the total size exceeds the maximum limit (80MB)
            if total_size > MAX_FILE_SIZE:
                return JsonResponse({'error': f'Total file size exceeds the maximum allowed size of 80MB.'}, status=400)

            # Create the FileUpload model with the provided serial
            file_upload = FileUpload(serial=serial)
            file_upload.save()  # Save the model to generate the directory

            # Now create files in the specified directory
            file_upload.create_files(files)

            return JsonResponse({'message': 'Files uploaded successfully!', 'serial': file_upload.serial}, status=201)

        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)


class FileUploadPagination(PageNumberPagination):
    page_size = 10  # Number of results per page (you can adjust this)
    page_size_query_param = 'page_size'  # Allow clients to specify the page size (optional)
    max_page_size = 100  # Max limit for page size (optional)


# views.py
# # Pagination for FileUpload

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Change this if you have specific permissions
def search_file_uploads(request):
    # Get query parameters from request
    serial = request.query_params.get('serial', None)
    
    # Create filter dictionary
    filters = {}
    if serial:
        filters['serial__icontains'] = serial  # Searching serial with partial match
    
    # Get and filter queryset with ID ordering
    file_uploads = FileUpload.objects.filter(**filters).order_by('id')
    
    # Paginate results
    paginator = FileUploadPagination()  # Ensure you have this pagination class
    paginated_queryset = paginator.paginate_queryset(file_uploads, request)
    
    # Serialize data
    serializer = FileUploadSerializer(paginated_queryset, many=True)
    
    # Return the response with pagination information and serialized data
    return Response({
        'total_file_uploads': file_uploads.count(),
        'total_pages': paginator.page.paginator.num_pages,
        'results': serializer.data
    })
