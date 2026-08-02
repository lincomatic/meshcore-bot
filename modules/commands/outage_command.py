#!/usr/bin/env python3
"""
Outage command for the MeshCore Bot.
Provides power outage information by ZIP code.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import requests

from ..models import MeshMessage
from ..utils import geocode_zipcode_sync
from .base_command import BaseCommand


class OutageCommand(BaseCommand):
    """Handle power outage lookups by US ZIP code."""

    name = "outage"
    keywords = ["outage", "outages","otg"]
    description = "Get power outage report by zip code (usage: outage <zipcode>)"
    category = "utility"
    cooldown_seconds = 5
    requires_internet = True

    short_description = "Get power outage status by ZIP code"
    usage = "outage <zipcode> [radius_miles]"
    examples = ["outage 91711", "outage 91711 10"]
    parameters = [
        {"name": "zipcode", "description": "5-digit US ZIP code"},
        {"name": "radius_miles", "description": "Optional search radius in miles (default: 5)"},
    ]

    API_URL = (
        "https://services.arcgis.com/BLN4oKB0N1YSgvY8/arcgis/rest/services/"
        "Power_Outages_(View)/FeatureServer/0/query"
    )

    def __init__(self, bot: Any):
        super().__init__(bot)
        self.outage_enabled = self.get_config_value("Outage_Command", "enabled", fallback=True, value_type="bool")
        self.url_timeout = 10
        self.default_radius = 5
        # Keep response compact for radio-friendly payload sizes.
        self.max_report_chars = 138

    def get_help_text(self) -> str:
        return "Usage: outage <zipcode> [radius_miles] - Example: outage 91711 or outage 91711 10"

    def can_execute(self, message: MeshMessage, skip_channel_check: bool = False) -> bool:
        if not self.outage_enabled:
            return False
        return super().can_execute(message, skip_channel_check=skip_channel_check)

    async def execute(self, message: MeshMessage) -> bool:
        content = message.content.strip()
        parts = content.split()

        if len(parts) < 2 or parts[1].lower() == "help":
            await self.send_response(message, self.get_help_text())
            return True

        zip_code = parts[1].strip()
        if not re.fullmatch(r"\d{5}", zip_code):
            await self.send_response(message, f"Invalid ZIP code '{zip_code}'. Use 5-digit US ZIP.")
            return True

        radius = self.default_radius
        if len(parts) >= 3:
            if not parts[2].isdigit():
                await self.send_response(message, f"Invalid Radius '{radius}.'")
                return True
            radius = max(1, min(int(parts[2]), 50))

        try:
            self.record_execution(message.sender_id)
            report = await self.get_outage_report(zip_code, radius)
            await self.send_response(message, report)
            return True
        except Exception as e:
            self.logger.error(f"Error in outage command: {e}")
            await self.send_response(message, f"Error getting outage data: {e}")
            return True

    async def get_outage_report(self, zip_code: str, radius: int) -> str:
        lat, lon = geocode_zipcode_sync(self.bot, zip_code, default_country="US", timeout=self.url_timeout)
        if lat is None or lon is None:
            return f"Error: Invalid zip code {zip_code}."

        params = {
            "f": "json",
            "geometry": f"{lon},{lat}",
            "geometryType": "esriGeometryPoint",
            "spatialRel": "esriSpatialRelIntersects",
            "distance": radius,
            "units": "esriSRUnit_StatuteMile",
            "inSR": "4326",
            "outFields": "UtilityCompany,ImpactedCustomers,EstimatedRestoreDate,StartDate,Cause",
            "returnGeometry": "false",
        }

        try:
            resp = requests.get(self.API_URL, params=params, timeout=self.url_timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return "Error: Outage API down."

        features = data.get("features", [])
        if not features:
            return f"{zip_code}: No active outages <{radius}mi."

        report = f"{zip_code}: "
        for feature in features:
            attrs = feature.get("attributes", {})
            utility = self._short_utility_name(attrs.get("UtilityCompany"))

            impacted_customers = attrs.get("ImpactedCustomers") or 0
            try:
                impacted_customers = int(impacted_customers)
            except Exception:
                impacted_customers = 0

            start_time = self._format_epoch_ms(attrs.get("StartDate"), fallback="Unk")
            restore_time = self._format_epoch_ms(attrs.get("EstimatedRestoreDate"), fallback="TBD")
            cause_raw = attrs.get("Cause")
            cause = str(cause_raw).strip() if cause_raw is not None else ""
            cause_part = f" : {cause}" if cause and cause.lower() != "unknown" else ""

            item = f"{utility} ({impacted_customers} off, Start: {start_time}, Fix: {restore_time}{cause_part}). "
            if len(report) + len(item) <= self.max_report_chars:
                report += item
            else:
                break

        return report.strip()

    @staticmethod
    def _short_utility_name(utility_raw: Any) -> str:
        utility_text = str(utility_raw or "Unknown")
        if "Edison" in utility_text:
            return "SCE"
        if "Pacific Gas" in utility_text:
            return "PG&E"
        if "San Diego" in utility_text:
            return "SDG&E"
        if "Sacramento" in utility_text:
            return "SMUD"
        if "Angeles" in utility_text:
            return "LAWP"
        return utility_text[:6]

    @staticmethod
    def _format_epoch_ms(epoch_ms: Any, fallback: str) -> str:
        if not epoch_ms:
            return fallback
        try:
            dt = datetime.fromtimestamp(float(epoch_ms) / 1000.0)
            return dt.strftime("%m/%d %I%p").replace(" 0", " ")
        except Exception:
            return fallback
