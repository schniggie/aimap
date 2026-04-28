"""Censys source adapter stub for the AIMap Discovery Engine.

This is a skeleton implementing :class:`SourceAdapter`.  All methods raise
``NotImplementedError`` until the Censys integration is built out.

Censys API field mapping
------------------------

Censys exposes host data via its v2 Search API.  Below is the mapping from
Censys response fields to AgentEndpoint schema fields:

+-----------------------------------+------------------------------+
| Censys field                      | AgentEndpoint field          |
+===================================+==============================+
| ``ip``                            | ``ip``                       |
+-----------------------------------+------------------------------+
| ``services[].port``               | ``port``                     |
+-----------------------------------+------------------------------+
| ``services[].tls.certificates``   | ``server.tls``               |
+-----------------------------------+------------------------------+
| ``services[].http.response``      | ``server.banner``            |
+-----------------------------------+------------------------------+
| ``services[].http.response``      | ``server.headers``           |
| ``.headers``                      |                              |
+-----------------------------------+------------------------------+
| ``dns.reverse_dns.names[]``       | ``hostname``                 |
+-----------------------------------+------------------------------+
| ``location.country``              | ``geo.country``              |
+-----------------------------------+------------------------------+
| ``location.country_code``         | ``geo.country_code``         |
+-----------------------------------+------------------------------+
| ``location.city``                 | ``geo.city``                 |
+-----------------------------------+------------------------------+
| ``location.coordinates.latitude`` | ``geo.lat``                  |
+-----------------------------------+------------------------------+
| ``location.coordinates.longitude``| ``geo.lon``                  |
+-----------------------------------+------------------------------+
| ``autonomous_system.asn``         | ``geo.asn``                  |
+-----------------------------------+------------------------------+
| ``autonomous_system.name``        | ``geo.org``                  |
+-----------------------------------+------------------------------+

Authentication
--------------
Censys requires two credentials:

* ``CENSYS_API_ID``  -- set via environment / ``.env``
* ``CENSYS_API_SECRET`` -- set via environment / ``.env``

Implementation notes
--------------------
* Use the ``censys`` Python SDK (``pip install censys``).
* The Censys search API uses a *cursor*-based pagination model -- iterate
  with ``CensysHosts().search(query, pages=N)``.
* Rate limits: 0.4 req/s (120 req / 5 min window) for free plans.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator

from app.discovery.base import SourceAdapter

logger = logging.getLogger(__name__)


class CensysAdapter(SourceAdapter):
    """Stub adapter for Censys host search.

    All methods raise ``NotImplementedError`` -- fill them in when the Censys
    integration is implemented.
    """

    @property
    def source_name(self) -> str:  # noqa: D401
        return "censys"

    async def search(self, query: str, max_results: int = 100) -> AsyncIterator[dict]:
        """Query Censys and yield raw result dicts.

        .. warning:: Not yet implemented.
        """
        raise NotImplementedError(
            "CensysAdapter.search() is not yet implemented. "
            "Install the censys SDK and add API credentials to proceed."
        )
        # Make this a valid async generator for type-checking purposes.
        yield  # pragma: no cover

    def normalize(self, raw: dict) -> dict:
        """Map a Censys host result to an AgentEndpoint-compatible dict.

        .. warning:: Not yet implemented.

        Expected implementation outline::

            ip = raw.get("ip", "")
            services = raw.get("services", [])
            for svc in services:
                port = svc.get("port", 0)
                tls = bool(svc.get("tls"))
                http_resp = svc.get("http", {}).get("response", {})
                headers = http_resp.get("headers", {})
                ...

            dns_names = raw.get("dns", {}).get("reverse_dns", {}).get("names", [])
            hostname = dns_names[0] if dns_names else ""

            loc = raw.get("location", {})
            geo = {
                "country": loc.get("country", ""),
                "country_code": loc.get("country_code", ""),
                "city": loc.get("city", ""),
                "lat": loc.get("coordinates", {}).get("latitude", 0.0),
                "lon": loc.get("coordinates", {}).get("longitude", 0.0),
                "asn": str(raw.get("autonomous_system", {}).get("asn", "")),
                "org": raw.get("autonomous_system", {}).get("name", ""),
            }

            return {"ip": ip, "port": port, "hostname": hostname, "geo": geo, ...}
        """
        raise NotImplementedError(
            "CensysAdapter.normalize() is not yet implemented."
        )
