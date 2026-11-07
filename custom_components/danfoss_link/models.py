"""Validated room state; the controller owns the temperature limits."""

import math
from dataclasses import dataclass
from typing import Any

from .protocol import CommandError, ProtocolError


def temperature(value: Any) -> float | None:
    if type(value) not in (int, float) or not math.isfinite(value) or value == 777:
        return None
    return float(value)


@dataclass(frozen=True)
class Room:
    id: int
    name: str
    current: float | None
    target: float | None
    minimum: float | None
    maximum: float | None
    adjustable: bool
    regulation_state: str | None

    @property
    def valid_limits(self) -> bool:
        return (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum < self.maximum
        )

    def validate_target(self, value: Any) -> float:
        target = temperature(value)
        if not self.adjustable or not self.valid_limits:
            raise CommandError(
                "Room setpoint is not adjustable or its limits are unavailable"
            )
        if target is None or not self.minimum <= target <= self.maximum:
            raise CommandError("Temperature is outside the controller's allowed range")
        return target

    @classmethod
    def parse(cls, raw: Any) -> "Room":
        if not isinstance(raw, dict) or type(raw.get("id")) is not int or raw["id"] < 0:
            raise ProtocolError("Room response has no valid numeric identity")
        if not isinstance(raw.get("name"), str) or not raw["name"].strip():
            raise ProtocolError("Room response has no valid name")
        setpoint = raw.get("setpoint")
        if not isinstance(setpoint, dict):
            setpoint = {}
        regulation_state = raw.get("regulationState")
        return cls(
            id=raw["id"],
            name=raw["name"],
            current=(
                None
                if raw.get("hasTemperatureSensor") is False
                else temperature(raw.get("ambientTemperature"))
            ),
            target=temperature(setpoint.get("temperature")),
            minimum=temperature(raw.get("minSetpoint")),
            maximum=temperature(raw.get("maxSetpoint")),
            adjustable=setpoint.get("type") == "Adjustable",
            regulation_state=(
                regulation_state if isinstance(regulation_state, str) else None
            ),
        )


def parse_rooms(raw: Any) -> dict[int, Room]:
    if not isinstance(raw, list):
        raise ProtocolError("Room response is not a list")
    rooms: dict[int, Room] = {}
    for value in raw:
        room = Room.parse(value)
        if room.id in rooms:
            raise ProtocolError("Room response contains duplicate identities")
        rooms[room.id] = room
    return rooms
