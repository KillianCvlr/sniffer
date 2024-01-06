CC ?= gcc
CFLAGS ?= -Wall -Wextra -g

LDLIBS?= -lpcap

INCLUDE_PATH = ./include

TARGET   = sniffer

SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin

SOURCES  := $(wildcard $(SRCDIR)/*.c $(SRCDIR)/protocols/*.c)
INCLUDES := $(wildcard $(INCLUDE_PATH)/*.h $(INCLUDE_PATH)/protocols/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

$(BINDIR)/$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	mkdir -p $(dir $@)
	$(CC) -o $@ -c $< $(CFLAGS) -I$(INCLUDE_PATH)

doc:
	doxygen Doxyfile

.PHONY: clean cov
clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(OBJDIR)/*.gcda
	rm -f $(OBJDIR)/*.gcno
	rm -f $(OBJDIR)/protocols/*.o
	rm -f $(OBJDIR)/protocols/*.gcda
	rm -f $(OBJDIR)/protocols/*.gcno
	rm -f $(BINDIR)/$(TARGET)
