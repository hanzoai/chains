VMS := $(shell ls -d */ 2>/dev/null | sed 's|/||' | grep -v '.github\|build\|node_modules')

.PHONY: all test clean $(VMS)

all: $(VMS)

$(VMS):
	cd $@ && go build -trimpath -ldflags="-s -w" -o ../build/$@ .

test:
	@for vm in $(VMS); do echo "=== $$vm ==="; cd $$vm && go test ./... && cd ..; done

clean:
	rm -rf build/
