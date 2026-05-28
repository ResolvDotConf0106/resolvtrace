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
	install -Dm755 $(TARGET)                          $(DESTDIR)$(BINDIR)/dns_sniffer
	install -Dm755 scripts/resolvtrace-monitor.sh     $(DESTDIR)$(BINDIR)/resolvtrace-monitor
	install -Dm644 systemd/resolvtrace.service        $(DESTDIR)$(SYSTEMD)/resolvtrace.service
	install -Dm644 systemd/resolvtrace-monitor.service $(DESTDIR)$(SYSTEMD)/resolvtrace-monitor.service
	install -Dm644 scripts/resolvtrace.logrotate      /etc/logrotate.d/resolvtrace
	mkdir -p $(DESTDIR)/var/log/resolvtrace
	systemctl daemon-reload
	systemctl enable --now resolvtrace
	systemctl enable --now resolvtrace-monitor
	@echo "resolvtrace installed and running!"

uninstall:
	systemctl stop resolvtrace resolvtrace-monitor       2>/dev/null || true
	systemctl disable resolvtrace resolvtrace-monitor    2>/dev/null || true
	rm -f $(BINDIR)/dns_sniffer
	rm -f $(BINDIR)/resolvtrace-monitor
	rm -f $(SYSTEMD)/resolvtrace.service
	rm -f $(SYSTEMD)/resolvtrace-monitor.service
	rm -f /etc/logrotate.d/resolvtrace

clean:
	rm -f $(TARGET)

deb: all
	bash scripts/build_deb.sh

rpm: all
	bash scripts/build_rpm.sh
