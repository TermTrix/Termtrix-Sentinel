import clickhouse_connect
from sentinel.app.config import settings



class ClickHouseStorage:
    def __init__(self):
        self.client = clickhouse_connect.get_client(
            host=settings.CH_HOST,
            user=settings.CH_USER,
            password=settings.CH_PASSWORD,
            secure=True
        )



connection = ClickHouseStorage()

# print(connection.client)