# Generated by Django 5.1.1 on 2024-11-01 23:18

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("server", "0009_post_created_at_post_updated_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="post",
            name="content",
            field=models.TextField(default=1),
            preserve_default=False,
        ),
    ]
