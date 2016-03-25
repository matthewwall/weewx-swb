weewx-swb

This is a driver for weewx that collects data from the SMA Sunny WebBox.
The webbox is a network interface to inverters on a photovoltaic system.

Installation

0) install weewx (see the weewx user guide)

1) download the driver

wget -O weewx-swb.zip https://github.com/matthewwall/weewx-swb/archive/master.zip

2) install the driver

wee_extension --install weewx-swb.zip

3) configure the driver

wee_config --reconfigure

4) start weewx

sudo /etc/init.d/weewx start

Credits

Implementation of this driver was much easier thanks to the work by others,
including:

Joerg Raedler

  https://bitbucket.org/jraedler/sunnywebbox

Andrew Tridgell

  http://solar.tridgell.net/webbox/README.txt
