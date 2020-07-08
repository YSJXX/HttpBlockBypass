TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
SOURCES += \
        division.cpp \
        main.cpp

HEADERS += \
    header.h

