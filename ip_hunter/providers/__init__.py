"""Provider registry for IP Hunter."""

from .regru import RegruProvider
from .selectel import SelectelProvider
from .timeweb import TimewebProvider

PROVIDERS: dict[str, type] = {
    "selectel": SelectelProvider,
    "timeweb": TimewebProvider,
    "regru": RegruProvider,
}
