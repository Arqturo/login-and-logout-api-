from django.core.management.base import BaseCommand
from django.db import connections

class Command(BaseCommand):
    help = 'Realiza una consulta a la base de datos SQL Server'

    def handle(self, *args, **kwargs):
        # Aquí pones tu consulta
        with connections['sqlserver'].cursor() as cursor:
            cursor.execute("SELECT * FROM dbo.AFILIADOS")
            rows = cursor.fetchall()

            for row in rows:
                self.stdout.write(str(row))  