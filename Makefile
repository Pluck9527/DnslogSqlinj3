.PHONY: test selftest package clean

test:
	python3 -m unittest discover -s tests -t . -v

selftest:
	python3 dnslogsqlinj3.py --self-test

package:
	python3 -m pip install --no-build-isolation --no-deps -e .

clean:
	rm -rf build dist *.egg-info __pycache__ tests/__pycache__ .pytest_cache
