INCLUDEPATH += $$PWD
QT += serialport

###  DRIVERS ###

### Secugen SDA04 ###
HEADERS                += $$PWD/secugen_sda04.h $$PWD/ifingerprint.h
SOURCES                += $$PWD/secugen_sda04.cpp
LIBS 		       += -lwiringPiDev -lwiringPi
