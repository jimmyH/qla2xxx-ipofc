
QLogic Fibre Channel HBAs support IP over Fibre Channel (RFC2625). However, they
no longer include this functionality in the linux drivers.

I have taken the last known QLogic drivers (8.01.07) and ported the IPoFC support
on top of the 8.07.00.34.12 drivers.

This is work in progress, and will (probably) only ever support the use case I
needed this for... (4gb FC HBAs are pretty cheap on ebay, much cheaper than 10gbe
NICs, and easily supports longer distances)

* Currently only supports qla24xx HBAs
* Only tested on QLE2462 HBAs
* Only tested with a Point-to-Point link (ie private loop)
* Not tested with Storage traffic on same link
* Still work in progress
  * Leaks memory each time module is loaded/unloaded
  * Dies horribly with a high burst of traffic (when you exhaust the 32 pkt tx queue)
  * High throughput are not stable (drops after a short time)

Update:
  I am now pretty sure there is an issue with the underlying firmware (7.01.00).
  Whenever we push the throughput above ~700mbit/s the receiver is reporting lots of
  frames being discarded. If I keep the throughput below this (eg using 'tc' to traffic
  shape) then I get no packet loss. In comparison I can get >3gbit/s disk bandwidth
  over the link, so it is not a physical issue.
  Since this is worse than gigabit ethernet, I'm abandoning this unless anyone has any
  bright ideas.
  

