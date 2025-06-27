SUBDIRS := $(wildcard experiments/exp_*/.)


.SILENT: all

all: $(SUBDIRS)
	for dir in $(SUBDIRS); do \
		@echo "Building $$dir"; \
		$(MAKE) -C $$dir clean; \
		$(MAKE) -C $$dir; \
	done

clean: $(SUBDIRS)
	for dir in $(SUBDIRS); do \
		@echo "Cleaning $$dir"; \
		$(MAKE) -C $$dir clean; \
	done