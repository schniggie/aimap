"""AIMap Discovery Engine.

Exports the public interface of the discovery sub-package:

* :class:`SourceAdapter` -- abstract base class for all source adapters.
* :class:`ShodanAdapter` -- Shodan search adapter.
* :class:`CensysAdapter` -- Censys adapter stub.
* :class:`NucleiRunner` -- wrapper around the nuclei CLI.
* :class:`ScanOrchestrator` -- coordinates ingestion and active scans.
"""

from app.discovery.base import SourceAdapter
from app.discovery.censys_adapter import CensysAdapter
from app.discovery.nuclei_runner import NucleiRunner
from app.discovery.orchestrator import ScanOrchestrator
from app.discovery.shodan_adapter import ShodanAdapter

__all__ = [
    "SourceAdapter",
    "ShodanAdapter",
    "CensysAdapter",
    "NucleiRunner",
    "ScanOrchestrator",
]
