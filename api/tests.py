import io
import json

from django.test import TestCase, Client
from django.utils import timezone
from datetime import timedelta

from .models import Transfer, TransferChunk


def _init(client, transfer_id, total_chunks=2, **overrides):
    payload = {
        'id': transfer_id,
        'name': 'file.bin',
        'size': 10,
        'type': 'application/octet-stream',
        'total_chunks': total_chunks,
        'expiry_hours': 1,
        'self_destruct': False,
        'download_limit': 0,
    }
    payload.update(overrides)
    return client.post(
        '/api/transfer/init/',
        data=json.dumps(payload),
        content_type='application/json',
    )


def _upload_all_chunks(client, transfer_id, total_chunks=2):
    for seq in range(total_chunks):
        client.post(
            f'/api/transfer/{transfer_id}/upload/{seq}/',
            data={
                'chunk': io.BytesIO(f'chunk-{seq}'.encode()),
                'iv': f'iv{seq}',
                'original_size': 5,
            },
        )
    client.post(f'/api/transfer/{transfer_id}/complete/')


def _download_all_chunks(client, transfer_id, total_chunks=2):
    """Return list of (status_code) for each chunk seq, in order."""
    return [
        client.get(f'/api/transfer/{transfer_id}/chunk/{seq}/').status_code
        for seq in range(total_chunks)
    ]


class DownloadLimitRegressionTests(TestCase):
    """
    Regression tests for the bug where a link became unusable in a second
    browser/tab after the very first successful download, because the last
    chunk's file+row were deleted as a side effect of the (previously
    unenforced) download_limit reaching its default value of 1.
    """

    def test_unlimited_transfer_can_be_downloaded_from_multiple_browsers(self):
        client = Client()
        _init(client, 'tA', total_chunks=3, download_limit=0)
        _upload_all_chunks(client, 'tA', total_chunks=3)

        # "Browser 1" downloads the full transfer.
        statuses_1 = _download_all_chunks(client, 'tA', total_chunks=3)
        self.assertEqual(statuses_1, [200, 200, 200])

        # All chunks must still exist on the server afterwards.
        self.assertEqual(TransferChunk.objects.filter(transfer_id='tA').count(), 3)

        # "Browser 2" (a completely separate download session) must be able
        # to fetch every chunk too — this is the exact scenario that used to
        # fail with "Only N-1/N chunks received."
        statuses_2 = _download_all_chunks(client, 'tA', total_chunks=3)
        self.assertEqual(statuses_2, [200, 200, 200])

    def test_download_limit_one_blocks_a_second_full_download_attempt(self):
        client = Client()
        _init(client, 'tB', total_chunks=2, download_limit=1)
        _upload_all_chunks(client, 'tB', total_chunks=2)

        # First full download succeeds.
        statuses_1 = _download_all_chunks(client, 'tB', total_chunks=2)
        self.assertEqual(statuses_1, [200, 200])

        # Chunks are NOT deleted just because the limit was hit.
        self.assertEqual(TransferChunk.objects.filter(transfer_id='tB').count(), 2)

        # A second, brand-new download attempt (chunk 0 first) must now be
        # cleanly rejected with a clear error — not a silent, corrupted
        # partial download.
        res = client.get('/api/transfer/tB/chunk/0/')
        self.assertEqual(res.status_code, 410)
        self.assertIn('Download limit reached', res.json()['error'])

    def test_self_destruct_wipes_transfer_after_full_download(self):
        client = Client()
        _init(client, 'tC', total_chunks=2, self_destruct=True, download_limit=0)
        _upload_all_chunks(client, 'tC', total_chunks=2)

        statuses = _download_all_chunks(client, 'tC', total_chunks=2)
        self.assertEqual(statuses, [200, 200])

        self.assertFalse(Transfer.objects.filter(id='tC').exists())

        res = client.get('/api/transfer/tC/meta/')
        self.assertEqual(res.status_code, 404)

    def test_meta_reports_accurate_error_reason_after_limit_reached(self):
        """The receiver UI surfaces whatever `error` the API returns, so the
        API must keep returning distinct, accurate reasons (not just always
        succeeding/failing generically)."""
        client = Client()
        _init(client, 'tD', total_chunks=1, download_limit=1)
        _upload_all_chunks(client, 'tD', total_chunks=1)
        _download_all_chunks(client, 'tD', total_chunks=1)

        # Metadata is still visible after the limit is reached — receivers
        # should always be able to see file info until the link truly expires.
        meta_res = client.get('/api/transfer/tD/meta/')
        self.assertEqual(meta_res.status_code, 200)

        chunk_res = client.get('/api/transfer/tD/chunk/0/')
        self.assertEqual(chunk_res.status_code, 410)
        self.assertEqual(chunk_res.json()['error'], 'Download limit reached')

    def test_expired_transfer_returns_expired_error(self):
        client = Client()
        _init(client, 'tE', total_chunks=1, download_limit=0)
        _upload_all_chunks(client, 'tE', total_chunks=1)

        t = Transfer.objects.get(id='tE')
        t.expires_at = timezone.now() - timedelta(hours=1)
        t.save(update_fields=['expires_at'])

        res = client.get('/api/transfer/tE/meta/')
        self.assertEqual(res.status_code, 410)
        self.assertEqual(res.json()['error'], 'Transfer link has expired')
        self.assertFalse(Transfer.objects.filter(id='tE').exists())
