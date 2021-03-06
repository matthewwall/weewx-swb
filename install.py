# installer for the weewx-swb driver
# Copyright 2016 Matthew Wall, all rights reserved

from setup import ExtensionInstaller

def loader():
    return SWBInstaller()

class SWBInstaller(ExtensionInstaller):
    def __init__(self):
        super(SWBInstaller, self).__init__(
            version="0.6",
            name='swb',
            description='Capture weather data from SMA Sunny Webbox',
            author="Matthew Wall",
            author_email="mwall@users.sourceforge.net",
            config={
                'Accumulator': {
                    'grid_energy': {
                        'extractor': 'sum'}}},
            files=[('bin/user', ['bin/user/swb.py'])]
            )
