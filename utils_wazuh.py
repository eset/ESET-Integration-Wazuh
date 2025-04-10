import json
import logging
import typing as t
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from integration.models import EnvVariables
from integration.utils import LastDetectionTimeHandler, TransformerDetections


class TransformerDetectionsWazuh(TransformerDetections):
    def __init__(self, env_vars: EnvVariables) -> None:
        super().__init__(env_vars)

    async def _send_data_to_destination(
        self, validated_data: t.List[dict[str, t.Any]], last_detection: str | None
    ) -> tuple[str | None, bool]:
        try:
            with open(f"./eset_integration.log", "a") as fp:
                for dict_item in validated_data:
                    self.clean_up_elastic(dict_item)
                    fp.write(json.dumps({"eset": dict_item}) + "\n")
        except Exception as e:
            logging.error(e)
            return last_detection, False

        last_detection = max(validated_data, key=lambda detection: detection.get("occurTime")).get("occurTime")  # type: ignore
        return last_detection, True

    def clean_up_elastic(self, dict_item: dict[str, t.Any]) -> None:
        if not dict_item.get("networkCommunication"):
            del dict_item["networkCommunication"]
        if not dict_item.get("triggeringEvent"):
            del dict_item["triggeringEvent"]
        elif not dict_item.get("triggeringEvent").get("data"):
            del dict_item["triggeringEvent"]["data"]


class LastDetectionTimeHandlerWazuh(LastDetectionTimeHandler):
    def __init__(self, data_source: str, interval: int) -> None:
        self.file_name = "last_detection_time.yml"
        super().__init__(data_source, interval)

    def get_last_occur_time(self, data_source: t.Optional[str] = None, interval: int = 5) -> str:
        try:
            self.ldt = yaml.safe_load(Path(__file__).absolute().parent.joinpath(self.file_name).read_bytes())
        except FileNotFoundError as e:
            logging.error(e)
            raise FileNotFoundError(f"The {self.file_name} file is not found.")
        self.verify_last_detection_time_from_file(data_source)
        return (  # type: ignore
            self.ldt.get(data_source)
            if self.ldt.get(data_source) != ""
            else (datetime.now(timezone.utc) - timedelta(seconds=interval * 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    def verify_last_detection_time_from_file(self, data_source: str | None) -> None:
        if not self.ldt:
            logging.info("The last detection time file is empty.")
            self.ldt = {"EP": "", "EI": "", "ECOS": ""}
        if self.ldt.get(data_source) == None:
            self.ldt[data_source] = ""

    async def update_last_detection_time(self, cur_ld_time: t.Optional[str], data_source: str) -> None:
        if cur_ld_time and cur_ld_time != self.last_detection_time:
            self.get_last_occur_time(data_source)
            self.ldt[data_source] = self.prepare_date_plus_timedelta(cur_ld_time)
            with open(Path(__file__).absolute().parent.joinpath(self.file_name), "w") as file:
                yaml.safe_dump(self.ldt, file, default_flow_style=False, sort_keys=False)
