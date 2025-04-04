# Generated by Django 5.0.9 on 2025-02-11 16:49

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server", "0012_innerprestamo"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="innerprestamo",
            options={},
        ),
        migrations.AddField(
            model_name="innerprestamo",
            name="prestamo_id",
            field=models.IntegerField(default=1, unique=True),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="innerprestamo",
            name="enable",
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name="innerprestamo",
            name="name",
            field=models.CharField(max_length=255),
        ),
    ]
