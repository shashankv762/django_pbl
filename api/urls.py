from django.urls import path
from . import views

urlpatterns = [
    # Transfer lifecycle (sender)
    path('transfer/init/',                                   views.init_transfer,    name='init_transfer'),
    path('transfer/<str:transfer_id>/upload/<int:seq>/',     views.upload_chunk,     name='upload_chunk'),
    path('transfer/<str:transfer_id>/complete/',             views.complete_transfer, name='complete_transfer'),

    # Receiver endpoints
    path('transfer/<str:transfer_id>/meta/',                 views.transfer_meta,    name='transfer_meta'),
    path('transfer/<str:transfer_id>/chunk/<int:seq>/',      views.download_chunk,   name='download_chunk'),
    path('transfer/<str:transfer_id>/stream/',               views.chunk_stream,     name='chunk_stream'),

    # Library stats
    path('stats/',                                           views.get_stats,        name='get_stats'),
    path('lan/ip/',                                          views.get_lan_ip,       name='get_lan_ip'),


    # LAN peer discovery (real cross-device detection)
    path('lan/announce/',                                    views.lan_announce,     name='lan_announce'),
    path('lan/devices/',                                     views.lan_devices,      name='lan_devices'),

    # WebRTC P2P signaling
    path('webrtc/room/',                                     views.create_webrtc_room,    name='create_webrtc_room'),
    path('webrtc/<str:room_id>/poll/',                      views.webrtc_signal_poll,    name='webrtc_signal_poll'),
    path('webrtc/<str:room_id>/signal/',                     views.post_webrtc_signal,    name='post_webrtc_signal'),
    path('webrtc/<str:room_id>/stream/',                     views.webrtc_signal_stream,  name='webrtc_signal_stream'),
]
