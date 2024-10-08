# Generated by Django 5.1.1 on 2024-09-26 14:13

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server", "0003_customuser_full_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserCaja",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("CE_TRABAJADOR", models.CharField(max_length=100)),
                ("CO_UBICACION", models.CharField(max_length=100)),
                ("TIPOPERSONAL", models.CharField(max_length=100)),
                ("EMAIL", models.EmailField(max_length=255)),
                ("TELEFONOS", models.CharField(max_length=50)),
                ("CTABANCO", models.CharField(max_length=50)),
                ("DESCRIPCION", models.TextField(blank=True)),
            ],
        ),
    ]
