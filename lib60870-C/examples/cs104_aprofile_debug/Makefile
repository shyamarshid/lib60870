LIB60870_HOME=../..

PROJECT_BINARY_NAME = client_aprofile
PROJECT_SOURCES = cs104_client_aprofile_debug.c

include $(LIB60870_HOME)/make/target_system.mk
include $(LIB60870_HOME)/make/stack_includes.mk

# Link against the system provided mbedTLS libraries to satisfy the
# cryptographic dependencies of the A-profile example.
LDLIBS += -lmbedtls -lmbedcrypto -lmbedx509

all:	$(PROJECT_BINARY_NAME)

include $(LIB60870_HOME)/make/common_targets.mk


$(PROJECT_BINARY_NAME):	$(PROJECT_SOURCES) $(LIB_NAME)
	$(CC) $(CFLAGS) $(LDFLAGS) -g -o $(PROJECT_BINARY_NAME) $(PROJECT_SOURCES) $(INCLUDES) $(LIB_NAME) $(LDLIBS)

clean:
	rm -f $(PROJECT_BINARY_NAME)

