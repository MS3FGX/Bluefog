# App info
APPNAME = bluefog
VERSION = 0.0.4

# Compiler and options
CC = gcc
CFLAGS += -Wall -O2 -Wno-unused-function

# Libraries to link
LIBS = -lbluetooth -lpthread

# Files
SOURCES = bluefog.c bdaddr.c devicenames.h
DOCS = ChangeLog COPYING README

# Targets
# Build
$(APPNAME): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(LIBS) -o $(APPNAME)

# Build tarball
release: clean
	tar --exclude='.*' -C ../ -czvf /tmp/$(APPNAME)-$(VERSION).tar.gz $(APPNAME)-$(VERSION)

# Clean for dist
clean:
	rm -rf $(APPNAME) *.o *.txt *.log 

# Install to system
install: $(APPNAME)
	mkdir -p $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/usr/share/doc/$(APPNAME)-$(VERSION)/
	cp $(APPNAME) $(DESTDIR)/usr/bin/
	cp -a $(DOCS) $(DESTDIR)/usr/share/doc/$(APPNAME)-$(VERSION)/
	
# Upgrade from previous source install
upgrade: removeold install

# Remove current version from system
uninstall:
	rm -rf $(DESTDIR)/usr/share/doc/$(APPNAME)-$(VERSION)/
	rm -f $(DESTDIR)/usr/bin/$(APPNAME)

# Remove older versions
removeold:
	rm -rf $(DESTDIR)/usr/share/doc/$(APPNAME)*
	rm -f $(DESTDIR)/usr/bin/$(APPNAME)	
