docker_push_proftpd:
	docker build . -t jbeeson/proftpd-slim -f Dockerfile-proftpd-alpine-source
	docker push jbeeson/proftpd-slim

build_proftpd_136c:
	docker build --build-arg PROFTPD_VERSION=v1.3.6c -f Dockerfile-proftpd-alpine-source -t jbeeson/proftpd-slim:1.3.6c .	

docker_push_proftpd_136c: build_proftpd_136c
	docker push jbeeson/proftpd-slim:1.3.6c


build_proftpd_137rc3:
	docker build --build-arg PROFTPD_VERSION=v1.3.7rc3 -f Dockerfile-proftpd-alpine-source -t jbeeson/proftpd-slim:1.3.7rc3 .	

docker_push_proftpd_137rc3: build_proftpd_137rc3
	docker push jbeeson/proftpd-slim:1.3.7rc3
	

build_proftpd:
	docker build . -t jbeeson/proftpd-slim -f Dockerfile-proftpd-alpine-source

build_admin:
	docker build . -t jbeeson/proftpd-admin -f Dockerfile-admin

docker_push_admin: build_admin
	docker push jbeeson/proftpd-admin

test_users:
	docker build . -t proftpd-admin -f Dockerfile-admin
	bash tests/test_users.sh

