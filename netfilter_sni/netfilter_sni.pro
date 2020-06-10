TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
LIBS += -lpcap
SOURCES += \
        calchecksum.cpp \
        division.cpp \
        main.cpp

HEADERS += \
    calchecksum.h
