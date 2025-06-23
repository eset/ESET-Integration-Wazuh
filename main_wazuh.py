import asyncio
import logging
import time

from integration.main import ServiceClient
from integration.models import Config

from utils_wazuh import LastDataTimeHandlerWazuh, TransformerDataWazuh


class ServiceClientWazuh(ServiceClient):
    def __init__(self) -> None:
        super().__init__()

    def _get_config(self) -> Config:
        return Config("Wazuh", "1.2.0")

    def _get_transformer_data(self) -> TransformerDataWazuh:
        return TransformerDataWazuh(self.env_vars)

    def _get_last_data_time_handler(self, data_source: str) -> LastDataTimeHandlerWazuh:
        return LastDataTimeHandlerWazuh(data_source, self.env_vars.interval)


async def main() -> None:
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S"
    )
    service_client = ServiceClientWazuh()
    while True:
        try:
            await asyncio.gather(service_client.run(), asyncio.sleep(service_client.env_vars.interval * 60))
        except Exception as _:
            await asyncio.sleep(3 * service_client.env_vars.interval * 60)


if __name__ == "__main__":
    asyncio.run(main())
