# Generated by Django 5.0.9 on 2025-02-11 15:32

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server", "0011_customuser_birth_date_customuser_room_address"),
    ]

    operations = [
        migrations.CreateModel(
            name="InnerPrestamo",
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
                ("name", models.CharField(max_length=50, unique=True)),
                ("description", models.TextField(blank=True)),
                ("enable", models.BooleanField(default=True)),
            ],
            options={
                "verbose_name": "InnerPrestamo",
                "verbose_name_plural": "InnerPrestamos",
                "ordering": ["name"],
            },
        ),
    ]
