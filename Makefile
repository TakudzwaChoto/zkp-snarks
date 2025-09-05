PYTHON ?= python3

.PHONY: smoke
smoke:
	$(PYTHON) - << 'PY' \
	import sys, os; sys.path.append(os.getcwd()); \
	from scripts.smoke_test import main; \
	raise SystemExit(main()) \
	PY

