# Generated manually to match `py manage.py makemigrations` output for the
# download_limit default change (1 -> 0, i.e. unlimited by default).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_transfer_transferchunk_delete_encryptedfile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transfer',
            name='download_limit',
            field=models.IntegerField(default=0),
        ),
    ]
