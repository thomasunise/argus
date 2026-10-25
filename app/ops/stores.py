"""Where backups are kept: the local BACKUP_DIR (always, it is also the staging area), and optionally an S3 bucket
and an Azure blob container. Every store keeps the newest BACKUP_KEEP backups and deletes older ones.

Backup names start with a UTC timestamp, so sorting names sorts by age. Each backup has a `<name>.json`
manifest next to it in every store.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..core.config import Settings
from .backup import SUFFIX

log = logging.getLogger('argus.backup')


class Store:
    name = 'base'

    def put(self, path: Path) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def names(self) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def fetch(self, name: str, dest_dir: Path) -> Path:  # pragma: no cover - interface
        raise NotImplementedError

    def delete(self, name: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def prune(self, keep: int) -> list[str]:
        """Delete all but the newest `keep` backups (and their manifests). Returns the deleted names."""
        doomed = sorted(self.names())[:-keep] if keep > 0 else []
        deleted: list[str] = []
        for name in doomed:
            try:
                self.delete(name)
                deleted.append(name)
            except Exception:  # an Object Lock / immutability policy may refuse; that is the policy working
                log.warning('could not delete old backup %s from %s', name, self.name, exc_info=True)
        return deleted


def _is_backup(name: str) -> bool:
    return name.endswith(SUFFIX) and '/' not in name and not name.startswith('.')


class LocalStore(Store):
    name = 'local'

    def __init__(self, directory: Path):
        self.dir = Path(directory)

    def put(self, path: Path) -> None:
        if path.parent.resolve() != self.dir.resolve():
            raise ValueError('local backups are written directly into BACKUP_DIR')

    def names(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return [p.name for p in self.dir.iterdir() if p.is_file() and _is_backup(p.name)]

    def fetch(self, name: str, dest_dir: Path) -> Path:
        path = self._path(name)
        if not path.is_file():
            raise FileNotFoundError(name)
        return path

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)
        self._path(name).with_name(name + '.json').unlink(missing_ok=True)

    def _path(self, name: str) -> Path:
        if not _is_backup(name):
            raise ValueError(f'not a backup name: {name!r}')
        return self.dir / name


class S3Store(Store):
    name = 's3'

    def __init__(self, bucket: str, prefix: str):
        try:
            import boto3  # noqa: F401
        except ImportError as exc:
            raise RuntimeError('BACKUP_S3_BUCKET is set but boto3 is not installed; use the -extras image or install requirements-optional.txt') from exc
        self.bucket, self.prefix = bucket, prefix

    def _client(self):
        import boto3

        return boto3.client('s3')

    def put(self, path: Path) -> None:
        client = self._client()
        client.upload_file(str(path), self.bucket, self.prefix + path.name)
        sidecar = path.with_name(path.name + '.json')
        if sidecar.is_file():
            client.upload_file(str(sidecar), self.bucket, self.prefix + sidecar.name)

    def names(self) -> list[str]:
        client = self._client()
        names: list[str] = []
        token = None
        while True:
            kwargs = {'Bucket': self.bucket, 'Prefix': self.prefix}
            if token:
                kwargs['ContinuationToken'] = token
            page = client.list_objects_v2(**kwargs)
            for item in page.get('Contents', []) or []:
                name = item['Key'][len(self.prefix):]
                if _is_backup(name):
                    names.append(name)
            if not page.get('IsTruncated'):
                return names
            token = page.get('NextContinuationToken')

    def fetch(self, name: str, dest_dir: Path) -> Path:
        if not _is_backup(name):
            raise ValueError(f'not a backup name: {name!r}')
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / name
        self._client().download_file(self.bucket, self.prefix + name, str(dest))
        return dest

    def delete(self, name: str) -> None:
        client = self._client()
        client.delete_object(Bucket=self.bucket, Key=self.prefix + name)
        client.delete_object(Bucket=self.bucket, Key=self.prefix + name + '.json')


class AzureStore(Store):
    name = 'azure'

    def __init__(self, connection_string: str, container: str):
        try:
            from azure.storage.blob import BlobServiceClient  # noqa: F401
        except ImportError as exc:
            raise RuntimeError('BACKUP_AZURE_CONTAINER is set but azure-storage-blob is not installed; use the -extras image or install requirements-optional.txt') from exc
        self.connection_string, self.container = connection_string, container

    def _container(self):
        from azure.storage.blob import BlobServiceClient

        return BlobServiceClient.from_connection_string(self.connection_string).get_container_client(self.container)

    def put(self, path: Path) -> None:
        container = self._container()
        for item in (path, path.with_name(path.name + '.json')):
            if item.is_file():
                with open(item, 'rb') as fh:
                    container.upload_blob(item.name, fh, overwrite=False)

    def names(self) -> list[str]:
        return [b.name for b in self._container().list_blobs() if _is_backup(b.name)]

    def fetch(self, name: str, dest_dir: Path) -> Path:
        if not _is_backup(name):
            raise ValueError(f'not a backup name: {name!r}')
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / name
        with open(dest, 'wb') as fh:
            self._container().download_blob(name).readinto(fh)
        return dest

    def delete(self, name: str) -> None:
        container = self._container()
        container.delete_blob(name)
        try:
            container.delete_blob(name + '.json')
        except Exception:
            log.debug('no manifest to delete for %s', name)


def build_stores(settings: Settings) -> list[Store]:
    stores: list[Store] = [LocalStore(settings.backup_dir)]
    if settings.backup_s3_bucket:
        stores.append(S3Store(settings.backup_s3_bucket, settings.backup_s3_prefix))
    if settings.backup_azure_container and settings.backup_azure_connection_string:
        stores.append(AzureStore(settings.backup_azure_connection_string, settings.backup_azure_container))
    return stores
