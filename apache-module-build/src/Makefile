#############################################
#
# mod_mshield Makefile V1.0 by MSHIELD
#
#############################################

# Change the pcre path to your real pcre path:
PCRE = /opt/applic/pcre-8.39/include

# mod_mshield shared memory space for sessions and cookies
SESSIONCOUNT = 100000
COOKIECOUNT = 300000

# Docker hub publishing parameters
BUILDTAG = latest
HUBPREFIX = markovshield

#############################################
#
# IMPORTANT: Do not change anything below
# here unless you excactly know what
# you are doing!
#
#############################################
APXSFLAGS = -I$(PCRE) -v -c
APXSFLAGSEND = -Wc,-O0 -Wc,-Wall -Wc,-DMOD_MSHIELD_SESSION_COUNT=100000 -Wc,-DMOD_MSHIELD_COOKIESTORE_COUNT=300000 -Wc,-Wno-unused-function
DEBUGFLAGS = -Wc,-g -Wc,-pg -Wc,-finstrument-functions -Wc,-fno-omit-frame-pointer
LIBS = -lrdkafka -lz -lpthread -lm -lhiredis

# Check if its Linux or Darwin (macOS)
UNAME = $(shell uname)
ifeq ($(UNAME), Linux)
LIBS += -lrt
endif

SRC = 													\
	mod_mshield.c 								\
	mod_mshield_regexp.c 					\
	mod_mshield_redirect.c 				\
	mod_mshield_cookie.c 					\
	mod_mshield_access_control.c 	\
	mod_mshield_request_filter.c 	\
	mod_mshield_response_filter.c	\
	mod_mshield_config.c 					\
	mod_mshield_session.c 				\
	mod_mshield_shm.c 						\
	mod_mshield_kafka.c 					\
	mod_mshield_redis.c 					\
	cJSON.c

dev: APXSCMD = apxs
dev: APXSFLAGS += $(APXSFLAGSEND)
dev: APXSFLAGS += $(DEBUGFLAGS)

deploy: APXSCMD = /opt/applic/httpd/bin/apxs
deploy: APXSFLAGS += -a -i $(APXSFLAGSEND)

docker-compile: APXSCMD = apxs
docker-compile: APXSFLAGS += -a -i $(APXSFLAGSEND)

compile:
	docker run --rm 								\
	-v `pwd`:/opt 									\
	ibuetler/hl-cas \
	/bin/bash -c 'make docker-compile && cp /usr/local/apache2/modules/mod_mshield.so /opt'

compile-librdkafka:
	docker run --rm 								\
	-v `pwd`:/opt 									\
	ibuetler/hl-cas 		\
	/bin/bash -c 'cp /tmp/librdkafka/src/librdkafka.so.1 /opt/'

prepare-publish: compile compile-librdkafka
#	docker build -f examplesite/reverseproxy/Dockerfile -t $(HUBPREFIX)/mshield-demo-reverse-proxy .
#	docker build -f examplesite/backend/Dockerfile -t $(HUBPREFIX)/mshield-demo-backend .
#	docker tag markovshield/mshield-demo-reverse-proxy markovshield/mshield-demo-reverse-proxy:$(BUILDTAG)
#	docker tag markovshield/mshield-demo-backend markovshield/mshield-demo-backend:$(BUILDTAG)
#	docker push markovshield/mshield-demo-reverse-proxy:$(BUILDTAG)
#	docker push markovshield/mshield-demo-backend:$(BUILDTAG)

publish: prepare-publish clean

all: APXSCMD = apxs
all: APXSFLAGS += $(APXSFLAGSEND)

all dev deploy docker-compile: mod_mshield

mod_mshield: $(SRC)
	$(APXSCMD) $(APXSFLAGS) $(SRC) $(LIBS)

docs:
	doxygen Doxyfile
	@echo "Documentation generated in docs"

clean-docs:
	rm -rf docs

clean:
	rm -rf *.la *.slo *.o *.lo .libs *.so *.so.1

.PHONY: mod_mshield dev deploy docker-compile compile compile-librdkafka prepare-publish shutdown-demo demo publish all docs clean-docs clean
