# Generated by Django 3.2.3 on 2021-10-20 10:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(default='', max_length=255, unique=True, verbose_name='이메일'),
            preserve_default=False,
        ),
    ]