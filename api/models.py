from django.db import models
from django.utils import timezone


class Transfer(models.Model):
    """
    Represents a single file transfer session.
    The file is uploaded in encrypted chunks; receiver downloads in real-time.
    The raw decryption key NEVER touches the server — it lives in the URL fragment.
    """
    id = models.CharField(max_length=50, primary_key=True)

    # File identity
    name = models.CharField(max_length=255)
    size = models.BigIntegerField()          # original (plaintext) file size in bytes
    type = models.CharField(max_length=100)

    # Chunking metadata
    chunk_size = models.IntegerField(default=524288)   # 512 KB per chunk
    total_chunks = models.IntegerField(default=1)
    uploaded_chunks = models.IntegerField(default=0)
    is_complete = models.BooleanField(default=False)   # sender has finished

    # Cryptography (hex-encoded)
    # For password-protected transfers:
    #   wrapped_key  = AES-GCM(pwdKey, fileKey)
    #   salt         = PBKDF2 salt
    #   wrap_iv      = IV used to wrap the file key
    # For non-password transfers, all three are empty — key is in URL fragment only.
    salt = models.CharField(max_length=200, blank=True, null=True)
    wrap_iv = models.CharField(max_length=100, blank=True, null=True)
    wrapped_key = models.CharField(max_length=512, blank=True, null=True)

    # Access control
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    self_destruct = models.BooleanField(default=False)
    download_limit = models.IntegerField(default=0)   # 0 = unlimited
    download_count = models.IntegerField(default=0)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.name} [{self.uploaded_chunks}/{self.total_chunks}] ({self.id})"


class TransferChunk(models.Model):
    """
    One encrypted slice of the file.
    Each chunk is independently AES-256-GCM encrypted with its own 12-byte IV
    so the receiver can decrypt and save it immediately without waiting for
    the remaining chunks (true Wormhole-style streaming).
    """
    transfer = models.ForeignKey(Transfer, on_delete=models.CASCADE, related_name='chunks')
    seq = models.IntegerField()                        # 0-indexed position
    iv = models.CharField(max_length=100)              # hex-encoded 12-byte IV for this chunk
    data = models.FileField(upload_to='chunks/')       # encrypted chunk bytes
    original_size = models.IntegerField()              # plaintext size of this chunk
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('transfer', 'seq')
        ordering = ['seq']

    def __str__(self):
        return f"Chunk {self.seq} of {self.transfer.name}"


class WebRTCRoom(models.Model):
    """
    A short-lived signaling room for WebRTC P2P negotiation.
    Expires after 10 minutes; signals (offer/answer/ICE) are stored here
    so peers can exchange them without WebSockets.
    """
    id = models.CharField(max_length=16, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"WebRTCRoom {self.id} (expires {self.expires_at})"


class WebRTCSignal(models.Model):
    """
    One signaling message in a WebRTC negotiation.
    sender: 'initiator' (the file sender) | 'responder' (the file receiver)
    type:   'offer' | 'answer' | 'ice-candidate' | 'bye'
    payload: arbitrary JSON — SDP string or RTCIceCandidateInit dict
    """
    room = models.ForeignKey(WebRTCRoom, on_delete=models.CASCADE, related_name='signals')
    sender = models.CharField(max_length=16)   # 'initiator' | 'responder'
    type = models.CharField(max_length=32)     # 'offer' | 'answer' | 'ice-candidate' | 'bye'
    payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return f"{self.type} from {self.sender} in room {self.room_id}"
