docker_push_proftpd:
	docker build . -t jbeeson/proftpd-slim -f Dockerfile-proftpd-alpine-source
	docker push jbeeson/proftpd-slim


build_proftpd:
	docker build . -t jbeeson/proftpd-slim -f Dockerfile-proftpd-alpine-source

build_admin:
	docker build . -t jbeeson/proftpd-admin -f Dockerfile-admin

docker_push_admin: build_admin
	docker push jbeeson/proftpd-admin

test_users:
	docker build . -t proftpd-admin -f Dockerfile-admin
	bash tests/test_users.sh

