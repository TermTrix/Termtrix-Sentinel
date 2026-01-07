import clickhouse_connect
# from sentinel.app.config import settings


CH_PASSWORD="6vTR6GF~QtbAS"
CH_USER="default"
CH_HOST="vxcfphwoh3.ap-south-1.aws.clickhouse.cloud"


class ClickHouseStorage:
    def __init__(self):
        self.client = clickhouse_connect.get_client(
            host=CH_HOST,
            user=CH_USER,
            password=CH_PASSWORD,
            secure=True
        )



connection = ClickHouseStorage()

# print(connection.client)