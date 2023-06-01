# Generated by Django 4.2.1 on 2023-06-01 18:10

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Medication',
            fields=[
                ('ID', models.AutoField(primary_key=True, serialize=False)),
                ('medication_name', models.CharField(max_length=100)),
                ('brand', models.CharField(max_length=100)),
                ('type', models.CharField(choices=[('L', 'Liquid'), ('T', 'Tablet'), ('C', 'Capsule')], max_length=1)),
                ('description', models.TextField()),
            ],
        ),
        
        migrations.CreateModel(
            name='Patient',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone', models.CharField(max_length=20)),
                ('name', models.CharField(max_length=20)),
                ('address', models.CharField(max_length=200)),
                ('email', models.CharField(max_length=200)),
                ('gender', models.CharField(choices=[('M', 'Male'), ('F', 'Female')], max_length=1)),
                ('dob', models.DateField()),
                ('username', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Therapist',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone', models.CharField(max_length=20)),
                ('specialization', models.CharField(max_length=100)),
                ('qualification', models.CharField(max_length=200)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TreatmentPlan',
            fields=[
                ('ID', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=100)),
                ('Psychological_symptoms', models.TextField()),
                ('Psychological_treatments', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='Treatment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('goals', models.TextField()),
                ('objectives', models.TextField()),
                ('interventions', models.TextField()),
                ('progress_notes', models.TextField()),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.patient')),
                ('plan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.treatmentplan')),
                ('therapist', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.therapist')),
            ],
        ),
        migrations.CreateModel(
            name='SessionTreatment',
            fields=[
                ('ID', models.AutoField(primary_key=True, serialize=False)),
                ('datetime_session', models.DateTimeField()),
                ('progress', models.TextField()),
                ('assessment_scores', models.TextField()),
                ('recommendations', models.TextField()),
                ('treatment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.treatment')),
            ],
        ),
        migrations.CreateModel(
            name='MedicationTreatment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dosage', models.CharField(max_length=50)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('medication', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.medication')),
                ('prescribing_therapist', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.therapist')),
                ('treatment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.treatment')),
            ],
        ),
        migrations.CreateModel(
            name='ChatHistory',
            fields=[
                ('IDchat', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField()),
                ('user_message', models.TextField()),
                ('chatbot_responses', models.TextField()),
                ('e_counselling', models.BooleanField(default=False)),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.patient')),
            ],
        ),
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('notes', models.TextField()),
                ('datetimeApp', models.DateTimeField()),
                ('status', models.CharField(choices=[('P', 'Pending'), ('C', 'Confirmed'), ('D', 'Done'), ('C', 'Canceled')], max_length=1)),
                ('confirmed', models.BooleanField(default=False)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.therapist')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='modules.patient')),
            ],
        ),
    ]
