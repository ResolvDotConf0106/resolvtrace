CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDFLAGS = -lpcap
TARGET  = dns_sniffer
SRC     = src/dns_sniffer.c
PREFIX  = /usr
BINDIR  = $(PREFIX)/bin
SYSTEMD = /etc/systemd/system

.PHONY: all clean install uninstall deb rpm

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

install: $(TARGET)
	install -Dm755 $(TARGET)                    $(DESTDIR)$(BINDIR)/$(TARGET)
	install -Dm644 systemd/resolvtrace.service  $(DESTDIR)$(SYSTEMD)/resolvtrace.service
	mkdir -p $(DESTDIR)/var/log/resolvtrace
	@echo "Run: systemctl daemon-reload && systemctl enable --now resolvtrace"

uninstall:
	systemctl stop resolvtrace    2>/dev/null || true
	systemctl disable resolvtrace 2>/dev/null || true
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(SYSTEMD)/resolvtrace.service

clean:
	rm -f $(TARGET)

deb: all
	bash scripts/build_deb.sh

rpm: all
	bash scripts/build_rpm.sh
