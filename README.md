# iamt-lms
Linux Kernel tools supporting Intel® Active Management Technology - Local Manager Service (LMS) for Linux 
**Intel AMT - OpenSource Tools**

## Getting Started
This tool is originaly hosted here: https://sourceforge.net/projects/openamt/. Because the last update for this tool it was in 2017-01-19 the sources didn't worked anymore with newer Linux Kernels.

## What's new
Nothing is new, I've just fixed the source code to access the correct /dev/mei0 instead /dev/mei device. Seems that in the past the Linux MEI driver created a /dev/mei device, the newer drivers creates /dev/meiX devices, but of course because there is only one AMT on the computer and the driver will be named this device as /dev/mei0.

## Building and other stuff
Please read https://github.com/AdrianBan/iamt-lms/blob/master/README

## License
Please read https://github.com/AdrianBan/iamt-lms/blob/master/COPYING

