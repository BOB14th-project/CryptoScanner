QT += widgets
CONFIG += c++17
SOURCES += gui_main_linux.cpp CryptoScanner.cpp FileScanner.cpp PatternDefinitions.cpp
HEADERS += CryptoScanner.h FileScanner.h PatternDefinitions.h

QMAKE_EXTRA_TARGETS += rebuild
rebuild.CONFIG = phony
rebuild.target = rebuild
rebuild.commands = $(MAKE) distclean && $(QMAKE) CryptoScanner.pro && $(MAKE) -j$$(nproc)
