from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        # Enable WAL journal mode for SQLite on every new connection.
        # WAL allows concurrent readers while a writer holds the lock,
        # dramatically reducing contention under rapid parallel requests
        # (e.g. 3 chunk downloads hitting the same row's download_count).
        from django.db.backends.signals import connection_created

        def _set_wal(sender, connection, **kwargs):
            if connection.vendor == 'sqlite':
                connection.cursor().execute('PRAGMA journal_mode=WAL;')
                connection.cursor().execute('PRAGMA synchronous=NORMAL;')
                connection.cursor().execute('PRAGMA busy_timeout=20000;')

        connection_created.connect(_set_wal)
