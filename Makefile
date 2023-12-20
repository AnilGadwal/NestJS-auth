.PHONY: build push

build:
	docker build -t "${IMAGE}" .

push:
	docker push "${IMAGE}"