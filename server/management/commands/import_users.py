import pandas as pd
from django.core.management.base import BaseCommand
from server.models import UserCaja  # Adjust this import

class Command(BaseCommand):
    help = 'Import users from an Excel file into the UserCaja model'

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str, help='The path to the Excel file')

    def handle(self, *args, **kwargs):
        file_path = kwargs['file_path']
        
        try:
            # Load the Excel file
            df = pd.read_excel(file_path)

            # Prepare a list for bulk creation
            users = [
                UserCaja(
                    CE_TRABAJADOR=row['CE_TRABAJADOR'],
                    CO_UBICACION=row['CO_UBICACION'],
                    TIPOPERSONAL=row['TIPOPERSONAL'],
                    EMAIL=row['EMAIL'],
                    TELEFONOS=row['TELEFONOS'],
                    CTABANCO=row['CTABANCO'],
                    DESCRIPCION=row['DESCRIPCION'],
                )
                for index, row in df.iterrows()
            ]

            # Bulk create users
            UserCaja.objects.bulk_create(users)

            self.stdout.write(self.style.SUCCESS('Successfully imported users from Excel file.'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error importing users: {e}'))
