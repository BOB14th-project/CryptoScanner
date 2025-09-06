QT += core gui widgets
CONFIG += c++17

SOURCES += \
    gui_main_linux.cpp \
    CryptoScanner.cpp \
    FileScanner.cpp \
    PatternDefinitions.cpp \
    PatternLoader.cpp

HEADERS += \
    CryptoScanner.h \
    FileScanner.h \
    PatternDefinitions.h \
    PatternLoader.h

QMAKE_EXTRA_TARGETS += rebuild
rebuild.CONFIG = phony
rebuild.target = rebuild
rebuild.commands = $(MAKE) distclean; $$QMAKE_QMAKE $$PWD/CryptoScanner.pro; $(MAKE) -j$$(nproc)

# Optional: miniz for in-jar scan without external unzip
# DEFINES += USE_MINIZ
# INCLUDEPATH += $$PWD/third_party/miniz
# SOURCES += third_party/miniz/miniz.c
