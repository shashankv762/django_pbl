from django.contrib import admin
from .models import Transfer, TransferChunk, WebRTCRoom, WebRTCSignal


class TransferChunkInline(admin.TabularInline):
    """Show all chunks of a transfer inline in the Transfer admin page."""
    model = TransferChunk
    extra = 0
    readonly_fields = ('seq', 'iv', 'data', 'original_size', 'uploaded_at')
    can_delete = False


@admin.register(Transfer)
class TransferAdmin(admin.ModelAdmin):
    list_display  = ('id', 'name', 'size', 'type', 'is_complete', 'uploaded_chunks',
                      'total_chunks', 'download_count', 'download_limit',
                      'self_destruct', 'expires_at', 'created_at')
    list_filter   = ('is_complete', 'self_destruct')
    search_fields = ('id', 'name')
    readonly_fields = ('id', 'created_at')
    ordering      = ('-created_at',)
    inlines       = [TransferChunkInline]

    def has_add_permission(self, request):
        # Transfers are created via the API, not manually
        return False


@admin.register(TransferChunk)
class TransferChunkAdmin(admin.ModelAdmin):
    list_display  = ('id', 'transfer', 'seq', 'original_size', 'uploaded_at')
    list_filter   = ('transfer',)
    search_fields = ('transfer__id', 'transfer__name')
    readonly_fields = ('transfer', 'seq', 'iv', 'data', 'original_size', 'uploaded_at')
    ordering      = ('transfer', 'seq')

    def has_add_permission(self, request):
        return False


class WebRTCSignalInline(admin.TabularInline):
    """Show all signals for a WebRTC room inline."""
    model = WebRTCSignal
    extra = 0
    readonly_fields = ('sender', 'type', 'payload', 'created_at')
    can_delete = False


@admin.register(WebRTCRoom)
class WebRTCRoomAdmin(admin.ModelAdmin):
    list_display  = ('id', 'created_at', 'expires_at')
    readonly_fields = ('id', 'created_at')
    ordering      = ('-created_at',)
    inlines       = [WebRTCSignalInline]

    def has_add_permission(self, request):
        return False


@admin.register(WebRTCSignal)
class WebRTCSignalAdmin(admin.ModelAdmin):
    list_display  = ('id', 'room', 'sender', 'type', 'created_at')
    list_filter   = ('sender', 'type')
    search_fields = ('room__id',)
    readonly_fields = ('room', 'sender', 'type', 'payload', 'created_at')
    ordering      = ('-created_at',)

    def has_add_permission(self, request):
        return False
