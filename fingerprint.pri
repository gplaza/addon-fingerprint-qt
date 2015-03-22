INCLUDEPATH += /mnt/rasp-pi-rootfs/usr/include/libusb-1.0/ $$PWD
DEPENDPATH += /mnt/rasp-pi-rootfs/usr/include/libusb-1.0/ $$PWD
PRE_TARGETDEPS += /mnt/rasp-pi-rootfs/usr/lib/arm-linux-gnueabihf/libusb.a

HEADERS                += $$PWD/ifingerprint.h
QT                     += gui

###  DRIVERS ###

### Secugen SDA04 ###
HEADERS                += $$PWD/secugen_sda04.h
SOURCES                += $$PWD/secugen_sda04.cpp
LIBS 		       += -lwiringPiDev -lwiringPi

LIBS 		       += -L/mnt/rasp-pi-rootfs/usr/lib/arm-linux-gnueabihf/ -lusb-1.0 -lrt
