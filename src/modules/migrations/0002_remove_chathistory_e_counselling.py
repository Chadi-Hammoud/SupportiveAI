# Generated by Django 4.2.1 on 2023-05-30 22:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('modules', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chathistory',
            name='e_counselling',
        ),
    ]
