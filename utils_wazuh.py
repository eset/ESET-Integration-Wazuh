import asyncio
import json
import logging
import typing as t
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from aiohttp import ClientSession
from integration.models import DataSource, EnvVariables
from integration.utils import LastDataTimeHandler, TransformerData


class TransformerDataWazuh(TransformerData):
    def __init__(self, env_vars: EnvVariables) -> None:
        super().__init__(env_vars)

    async def _send_data_to_destination(
        self,
        validated_data: t.List[dict[str, t.Any]],
        last_data: str | None,
        endp: str = "",
        lock: t.Optional[asyncio.Lock] = None,
        session: t.Optional[ClientSession] = None,
    ) -> tuple[str | None, bool]:
        assert lock
        async with lock:
            try:
                with open(f"./eset_integration.log", "a") as fp:
                    for dict_item in validated_data:
                        if not "incidents" in endp:
                            self.clean_up_elastic(dict_item)
                        fp.write(json.dumps({"eset": dict_item}) + "\n")
            except Exception as e:
                logging.error(e)
                return last_data, False

        if "incidents" in endp:
            last_data = max(validated_data, key=lambda data: data.get("createTime") or "").get("createTime")
        return last_data, True

    def clean_up_elastic(self, dict_item: dict[str, t.Any]) -> None:
        if not dict_item.get("networkCommunication"):
            del dict_item["networkCommunication"]

        triggering_event = dict_item.get("triggeringEvent")
        if not triggering_event:
            del dict_item["triggeringEvent"]
        elif not triggering_event.get("data"):
            del dict_item["triggeringEvent"]["data"]


class LastDataTimeHandlerWazuh(LastDataTimeHandler):
    def __init__(self, data_source: DataSource, interval: int) -> None:
        self.file_name = "last_detection_time.yml"
        super().__init__(data_source, interval)

    def get_last_data_time(self, data_source: DataSource, interval: int = 5) -> tuple[str, str]:
        try:
            self.ldt = yaml.safe_load(Path(__file__).absolute().parent.joinpath(self.file_name).read_bytes())
        except FileNotFoundError as e:
            logging.error(e)
            raise FileNotFoundError(f"The {self.file_name} file is not found.")

        self.verify_last_data_time_from_file(data_source)

        if data_source == DataSource.INCIDENTS and self.ldt.get(data_source.name) == "":
            return (datetime.now(timezone.utc) - timedelta(minutes=10 * interval)).strftime("%Y-%m-%dT%H:%M:%SZ"), ""

        return self.ldt.get(data_source.name), self.ldt.get(f"{data_source.name}_NPT", "")

    def verify_last_data_time_from_file(self, data_source: DataSource) -> None:
        if not self.ldt:
            logging.info("The last detection time file is empty.")
            self.ldt = {"EP": "", "EI_ECOS": "", "EP_NPT": "", "EI_ECOS_NPT": "", "INCIDENTS": ""}
        if self.ldt.get(data_source.name) == None:
            self.ldt[data_source.name] = ""

    async def update_last_data_time(
        self, cur_ld_time: t.Optional[str], next_page_token: t.Optional[str], data_source: DataSource
    ) -> None:
        self.get_last_data_time(data_source)
        updates: dict[str, t.Any] = {}

        if data_source == DataSource.INCIDENTS:
            if cur_ld_time and cur_ld_time != self.last_data_time:
                updates[data_source.name] = self.prepare_date_plus_timedelta(cur_ld_time)
        else:
            if next_page_token and next_page_token != self.next_page_token:
                updates[f"{data_source.name}_NPT"] = next_page_token
            elif cur_ld_time and cur_ld_time != self.last_data_time:
                updates.update({data_source.name: cur_ld_time, f"{data_source.name}_NPT": next_page_token})

        if updates:
            self.ldt.update(updates)
            with open(Path(__file__).absolute().parent.joinpath(self.file_name), "w") as file:
                yaml.safe_dump(self.ldt, file, default_flow_style=False, sort_keys=False)
            logging.info(f"Updated {self.file_name} file for {data_source}.")