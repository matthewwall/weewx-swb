weewx-swb

This is a driver for weewx that collects data from the SMA Sunny Webbox.
The webbox is a network interface to inverters on a photovoltaic system.

Installation

0) install weewx

(see the weewx user guide)

1) install the swb driver

wee_extension --install weewx-sma

2) configure the driver

wee_config --reconfigure

3) start weewx

sudo /etc/init.d/weewx start

Credits

Implementation of this driver was much easier thanks to the work by others,
including:

Joerg Raedler

  https://bitbucket.org/jraedler/sunnywebbox

Andrew Tridgell for a simple python implementation and pvoutput uploader:

  http://solar.tridgell.net/webbox/README.txt
