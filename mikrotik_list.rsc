# Mikrotik Address-List generated on 2025-08-05T02:46:03.751Z

:local exists [/ip firewall address-list find address="edge-mqtt-fallback.facebook.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="edge-mqtt-fallback.facebook.com" comment="edge-mqtt-fallback.facebook.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr1.sn-npoldn76.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr1.sn-npoldn76.googlevideo.com" comment="rr1.sn-npoldn76.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="mqtt.fallback.c10r.facebook.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="mqtt.fallback.c10r.facebook.com" comment="mqtt.fallback.c10r.facebook.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr1---sn-npoldn76.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr1---sn-npoldn76.googlevideo.com" comment="rr1---sn-npoldn76.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr3.sn-npoe7ns6.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr3.sn-npoe7ns6.googlevideo.com" comment="rr3.sn-npoe7ns6.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr2.sn-npoeeney.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr2.sn-npoeeney.googlevideo.com" comment="rr2.sn-npoeeney.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="gateway.facebook.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="gateway.facebook.com" comment="gateway.facebook.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="a1091.dscapi7.akamai.net" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="a1091.dscapi7.akamai.net" comment="a1091.dscapi7.akamai.net" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="a2047.dscapi9.akamai.net" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="a2047.dscapi9.akamai.net" comment="a2047.dscapi9.akamai.net" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="a1405.t.akamai.net" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="a1405.t.akamai.net" comment="a1405.t.akamai.net" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="tpg16-normal.tiktokv.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="tpg16-normal.tiktokv.com" comment="tpg16-normal.tiktokv.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr1---sn-npoldn7y.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr1---sn-npoldn7y.googlevideo.com" comment="rr1---sn-npoldn7y.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="www.youtube.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="www.youtube.com" comment="www.youtube.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr2---sn-npoldn7s.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr2---sn-npoldn7s.googlevideo.com" comment="rr2---sn-npoldn7s.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr1---sn-apou5n5gu5-jb36.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr1---sn-apou5n5gu5-jb36.googlevideo.com" comment="rr1---sn-apou5n5gu5-jb36.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr1.sn-apou5n5gu5-jb36.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr1.sn-apou5n5gu5-jb36.googlevideo.com" comment="rr1.sn-apou5n5gu5-jb36.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr2.sn-npoldn7d.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr2.sn-npoldn7d.googlevideo.com" comment="rr2.sn-npoldn7d.googlevideo.com" timeout=1d00:00:00 }
:local exists [/ip firewall address-list find address="rr2---sn-npoldn7d.googlevideo.com" list="Sosmed"]
:if ($exists = "") do={ /ip firewall address-list add list="Sosmed" address="rr2---sn-npoldn7d.googlevideo.com" comment="rr2---sn-npoldn7d.googlevideo.com" timeout=1d00:00:00 }
