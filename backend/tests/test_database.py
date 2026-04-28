"""Tests for database connection and index initialization."""

import pytest
import pytest_asyncio
from mongomock_motor import AsyncMongoMockClient

from app.database import get_database, init_indexes, set_database


@pytest_asyncio.fixture(autouse=True)
async def mock_db():
    """Replace the real database with a mongomock-motor instance."""
    client = AsyncMongoMockClient()
    db = client["aimap_test"]
    set_database(db)
    yield db
    # Cleanup: drop the test database
    await client.drop_database("aimap_test")


class TestGetDatabase:
    """Test get_database returns a usable database object."""

    @pytest.mark.asyncio
    async def test_returns_database(self, mock_db):
        db = get_database()
        assert db is not None
        # Should be the mock database we injected
        assert db is mock_db

    @pytest.mark.asyncio
    async def test_has_collection_access(self, mock_db):
        db = get_database()
        endpoints = db["endpoints"]
        assert endpoints is not None


class TestInitIndexes:
    """Test that init_indexes runs without error."""

    @pytest.mark.asyncio
    async def test_init_indexes_succeeds(self, mock_db):
        """init_indexes should complete without raising."""
        await init_indexes()

    @pytest.mark.asyncio
    async def test_init_indexes_idempotent(self, mock_db):
        """Calling init_indexes twice should not raise."""
        await init_indexes()
        await init_indexes()

    @pytest.mark.asyncio
    async def test_endpoints_collection_has_indexes(self, mock_db):
        """After init, the endpoints collection should have indexes."""
        await init_indexes()
        db = get_database()
        indexes = await db["endpoints"].index_information()
        # At minimum we expect the unique composite index + _id
        assert len(indexes) > 1

    @pytest.mark.asyncio
    async def test_analyses_collection_has_indexes(self, mock_db):
        await init_indexes()
        db = get_database()
        indexes = await db["analyses"].index_information()
        assert len(indexes) > 1

    @pytest.mark.asyncio
    async def test_scans_collection_has_indexes(self, mock_db):
        await init_indexes()
        db = get_database()
        indexes = await db["scans"].index_information()
        assert len(indexes) > 1

    @pytest.mark.asyncio
    async def test_ranges_collection_has_indexes(self, mock_db):
        await init_indexes()
        db = get_database()
        indexes = await db["ranges"].index_information()
        assert len(indexes) > 1
